//go:build desktop

package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/ui"
)

func init() {
	rootCmd.AddCommand(desktopCmd)
}

var desktopCmd = &cobra.Command{
	Use:   "desktop",
	Short: "start a desktop UI for gitleaks",
	Run:   runDesktop,
}

func runDesktop(cmd *cobra.Command, _ []string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitleaks desktop: %v\n", err)
		return
	}

	serverErr := make(chan error, 1)
	go func() {
		err := ui.ServeListener(listener, false)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		serverErr <- err
	}()

	localURL := fmt.Sprintf("http://%s", listener.Addr().String())
	parsedURL, _ := url.Parse(localURL)

	desktopApp := app.NewWithID("io.gitleaks.desktop")
	window := desktopApp.NewWindow("Gitleaks")
	window.Resize(fyne.NewSize(560, 280))

	status := widget.NewLabel("Desktop UI is running")
	status.TextStyle = fyne.TextStyle{Bold: true}

	urlEntry := widget.NewEntry()
	urlEntry.SetText(localURL)
	urlEntry.Disable()

	var closeOnce sync.Once
	closeApp := func() {
		closeOnce.Do(func() {
			_ = listener.Close()
			desktopApp.Quit()
		})
	}

	openButton := widget.NewButton("Open UI", func() {
		if parsedURL != nil {
			_ = desktopApp.OpenURL(parsedURL)
		}
	})

	copyButton := widget.NewButton("Copy URL", func() {
		window.Clipboard().SetContent(localURL)
	})

	quitButton := widget.NewButton("Quit", closeApp)
	window.SetCloseIntercept(closeApp)

	go func() {
		if err := <-serverErr; err != nil {
			fyne.Do(func() {
				status.SetText("Server stopped: " + err.Error())
			})
		}
	}()

	window.SetContent(container.NewBorder(
		nil,
		container.NewHBox(openButton, copyButton, quitButton),
		nil,
		nil,
		container.NewVBox(
			status,
			widget.NewLabel("Local URL"),
			urlEntry,
		),
	))

	window.ShowAndRun()
}
