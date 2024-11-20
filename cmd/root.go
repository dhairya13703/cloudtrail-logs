package cmd

import (
	"github.com/dhairya13703/cloudtrail-logs/cmd/kms"
	// "github.com/dhairya13703/cloudtrail-logs/cmd/sns"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	profile   string
	region    string
	outputDir string
)

var rootCmd = &cobra.Command{
	Use:   "github.com/dhairya13703/cloudtrail-logs",
	Short: "AWS Resource Monitor - CloudTrail event monitoring tool",
	Long: `AWS Resource Monitor helps you track AWS resource usage through CloudTrail logs.
It supports monitoring various services like KMS, EC2, SNS, and more.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	defaultOutputDir := fmt.Sprintf("%s/aws-monitor-logs", homeDir)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "default", "AWS profile to use")
	rootCmd.PersistentFlags().StringVar(&region, "region", "us-east-1", "AWS region to monitor")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output", defaultOutputDir, "Directory for log files")

	// Add service commands
	rootCmd.AddCommand(kms.NewKMSCmd())
	// rootCmd.AddCommand(ec2.NewEC2Cmd())
	// rootCmd.AddCommand(sns.NewSNSCmd())
}