package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"embed"

	"github.com/zricethezav/gitleaks/v8/logging"
)

//go:embed static
var staticFiles embed.FS

// scanState holds the state of the current (or most recent) scan.
type scanState struct {
	mu sync.Mutex

	running  bool
	done     bool
	scanErr  string
	logLines []string
	findings []json.RawMessage

	cancel context.CancelFunc
	// fan-out: any number of SSE connections can subscribe.
	subscribers map[chan string]struct{}
}

func newScanState() *scanState {
	return &scanState{
		subscribers: make(map[chan string]struct{}),
	}
}

func (s *scanState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.done = false
	s.scanErr = ""
	s.logLines = nil
	s.findings = nil
	s.cancel = nil
	for ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = make(map[chan string]struct{})
}

func (s *scanState) addLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logLines = append(s.logLines, line)
	for ch := range s.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}

func (s *scanState) subscribe() (chan string, func()) {
	ch := make(chan string, 512)
	s.mu.Lock()
	// Replay existing lines for late subscribers.
	for _, line := range s.logLines {
		ch <- line
	}
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	unsubscribe := func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
		// Drain so the goroutine that writes doesn't block.
		for range ch {
		}
	}
	return ch, unsubscribe
}

func (s *scanState) broadcastDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- "\x00DONE":
		default:
		}
	}
}

// Serve starts the UI HTTP server, optionally opens the browser, and blocks
// until the server stops.
func Serve(host string, port int, openBrowser bool) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	return ServeListener(ln, openBrowser)
}

// ServeListener starts the UI HTTP server on an existing listener and blocks
// until the server stops.
func ServeListener(ln net.Listener, openBrowser bool) error {
	state := newScanState()

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not locate gitleaks binary: %w", err)
	}

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("embedding static files: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// ── API ──
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		apiScan(w, r, state, binaryPath)
	})
	mux.HandleFunc("/api/scan/stream", func(w http.ResponseWriter, r *http.Request) {
		apiScanStream(w, r, state)
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		apiStop(w, r, state)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		apiStatus(w, r, state)
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		apiFindings(w, r, state)
	})

	url := fmt.Sprintf("http://%s", ln.Addr().String())
	logging.Info().Msgf("Gitleaks UI → %s  (press Ctrl-C to stop)", url)

	if openBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openURL(url)
		}()
	}

	return http.Serve(ln, mux)
}

// ── API handlers ──────────────────────────────────────────────────────────────

// apiScan accepts POST with JSON body of ScanOptions, starts a scan in the
// background, and returns 202 immediately.
func apiScan(w http.ResponseWriter, r *http.Request, state *scanState, binaryPath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.Lock()
	if state.running {
		state.mu.Unlock()
		http.Error(w, "scan already running", http.StatusConflict)
		return
	}
	state.mu.Unlock()

	var opts ScanOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	state.reset()
	ctx, cancel := context.WithCancel(context.Background())
	state.mu.Lock()
	state.running = true
	state.cancel = cancel
	state.mu.Unlock()

	logCh := make(chan string, 1024)

	// Fan-out goroutine: forward logCh lines to all SSE subscribers.
	go func() {
		for line := range logCh {
			state.addLog(line)
		}
	}()

	// Scan goroutine.
	go func() {
		findings, err := runScan(ctx, binaryPath, opts, logCh)
		close(logCh)

		state.mu.Lock()
		state.running = false
		state.done = true
		state.findings = findings
		if err != nil && ctx.Err() == nil {
			state.scanErr = err.Error()
		}
		state.mu.Unlock()
		state.broadcastDone()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"started"}`))
}

// apiScanStream is an SSE endpoint.  Clients connect via GET and receive
// log lines as they are produced by the running scan.
func apiScanStream(w http.ResponseWriter, r *http.Request, state *scanState) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsubscribe := state.subscribe()
	defer unsubscribe()

	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-ch:
			if !ok {
				// channel was closed (reset)
				_, _ = fmt.Fprintf(w, "event: done\ndata: \n\n")
				flusher.Flush()
				return
			}
			if line == "\x00DONE" {
				_, _ = fmt.Fprintf(w, "event: done\ndata: \n\n")
				flusher.Flush()
				return
			}
			// SSE format
			_, _ = fmt.Fprintf(w, "data: %s\n\n", sseEscape(line))
			flusher.Flush()
		}
	}
}

// apiStop cancels the running scan.
func apiStop(w http.ResponseWriter, r *http.Request, state *scanState) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state.mu.Lock()
	cancel := state.cancel
	state.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	jsonOK(w, map[string]string{"status": "stopped"})
}

// apiStatus returns the current scan status.
func apiStatus(w http.ResponseWriter, r *http.Request, state *scanState) {
	state.mu.Lock()
	resp := map[string]interface{}{
		"running":      state.running,
		"done":         state.done,
		"error":        state.scanErr,
		"findingCount": len(state.findings),
		"logLineCount": len(state.logLines),
	}
	state.mu.Unlock()
	jsonOK(w, resp)
}

// apiFindings returns the findings from the last completed scan.
func apiFindings(w http.ResponseWriter, r *http.Request, state *scanState) {
	state.mu.Lock()
	findings := state.findings
	state.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if findings == nil {
		_, _ = w.Write([]byte("[]"))
		return
	}
	_ = json.NewEncoder(w).Encode(findings)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// sseEscape replaces newlines in a log line so SSE data fields stay on one
// line.  Real newlines inside log output are replaced with the Unicode
// paragraph separator which browsers render fine.
func sseEscape(s string) string {
	return fmt.Sprintf("%q", s)
}
