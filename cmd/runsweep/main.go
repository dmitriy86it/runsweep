package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version, commit, date = "dev", "none", "unknown"

func main() {
	root := &cobra.Command{Use: "runsweep", SilenceUsage: true}
	root.AddCommand(&cobra.Command{Use: "version", Run: func(*cobra.Command, []string) {
		fmt.Printf("runsweep %s (%s, %s)\n", version, commit, date)
	}})
	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}
