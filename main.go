package main

import (
	"fmt"
	"os"

	"github.com/dhairya13703/cloudtrail-logs/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}