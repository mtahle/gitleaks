//go:build desktop

package main

import (
	"os"
	"os/signal"

	"github.com/zricethezav/gitleaks/v8/cmd"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func main() {
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "desktop")
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	cmd.Execute()
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	logging.Fatal().Msg("Interrupt signal received. Exiting...")
}
