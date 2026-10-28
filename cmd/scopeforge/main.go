package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MIGUEL-MOSCOSO-DEV/scopeforge/internal/recon"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	flags := flag.NewFlagSet("scopeforge", flag.ContinueOnError)
	configPath := flags.String("config", "", "scope configuration JSON")
	state := flags.String("state", "", "checkpoint path; required for a scan")
	cancelFile := flags.String("cancel-file", "", "optional local cancellation marker path")
	output := flags.String("out", "", "final report JSON path")
	baseline := flags.String("baseline", "", "previous report for a comparison")
	resume := flags.Bool("resume", false, "reuse completed targets from the matching checkpoint")
	check := flags.Bool("check", false, "validate configuration without network activity")
	authorized := flags.Bool("authorized", false, "confirm permission for the declared scope")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(os.Stderr, "Provide --config. Use --help for options.")
		return 2
	}
	config, err := recon.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	urls, err := config.URLs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *check {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "urls": len(urls), "network_activity": false})
		return 0
	}
	if !*authorized || *state == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "Scans require --authorized, --state and --out.")
		return 2
	}
	stateAbs, _ := filepath.Abs(*state)
	outAbs, _ := filepath.Abs(*output)
	if *baseline != "" {
		baselineAbs, _ := filepath.Abs(*baseline)
		if baselineAbs == stateAbs || baselineAbs == outAbs {
			fmt.Fprintln(os.Stderr, "Baseline must be a different file.")
			return 2
		}
	}
	var previous recon.Report
	if *baseline != "" {
		previous, err = recon.ReadReport(*baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *cancelFile != "" {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(*cancelFile); err == nil {
						stop()
						return
					}
				}
			}
		}()
	}
	report, err := recon.Run(ctx, config, *state, *resume, func(done, total int) { fmt.Fprintf(os.Stderr, "Progress %d/%d\n", done, total) })
	if *baseline != "" {
		report.Changes = recon.Compare(previous, report)
	}
	if len(report.Assets) > 0 || err == nil {
		if writeErr := recon.WriteReport(*output, report); writeErr != nil {
			fmt.Fprintln(os.Stderr, writeErr)
			return 2
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"complete": report.Complete, "assets": len(report.Assets), "changes": len(report.Changes), "report": *output})
	return 0
}
