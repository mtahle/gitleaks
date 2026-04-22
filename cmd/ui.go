package cmd

import (
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/ui"
)

func init() {
	rootCmd.AddCommand(uiCmd)
	uiCmd.Flags().String("host", "127.0.0.1", "host address to bind the UI server to")
	uiCmd.Flags().Int("port", 7777, "port to listen on")
	uiCmd.Flags().Bool("no-open", false, "do not automatically open the browser")
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "start a web UI for gitleaks",
	Long: `Launch a local web UI for Gitleaks.

The UI lets you configure and run any Gitleaks scan command (git, dir, stdin)
through a browser-based interface, stream live log output, browse findings in
an interactive table, and export reports in multiple formats.

The server listens on 127.0.0.1:7777 by default and opens the browser
automatically.`,
	Run: runUI,
}

func runUI(cmd *cobra.Command, _ []string) {
	host := mustGetStringFlag(cmd, "host")
	port := mustGetIntFlag(cmd, "port")
	noOpen := mustGetBoolFlag(cmd, "no-open")

	if err := ui.Serve(host, port, !noOpen); err != nil {
		logging.Fatal().Err(err).Msg("gitleaks UI server stopped")
	}
}
