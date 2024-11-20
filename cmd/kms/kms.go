// cmd/kms/kms.go
package kms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dhairya13703/cloudtrail-logs/internal/aws"
	"github.com/dhairya13703/cloudtrail-logs/internal/monitor"
	"github.com/dhairya13703/cloudtrail-logs/internal/timeutil"
	"github.com/dhairya13703/cloudtrail-logs/internal/writer"
	"github.com/spf13/cobra"
)

var (
	keyID      string
	lastN      string
	startTime  string
	endTime    string
	exportFile string
	exportFormat string
)

func NewKMSCmd() *cobra.Command {
	kmsCmd := &cobra.Command{
		Use:   "kms",
		Short: "Monitor KMS events",
		Long: `Monitor AWS KMS key usage and events through CloudTrail logs.
		
Time Range Options:
  1. Relative time (--last-n):
     - Minutes: e.g., --last-n 5m (last 5 minutes)
     - Hours: e.g., --last-n 2h (last 2 hours)
     Maximum: 24 hours

  2. Custom time range (--start and --end):
     Format options:
     - YYYY-MM-DD HH:mm:ss
     - YYYY-MM-DD HH:mm
     - YYYY-MM-DD (will use full day)
     Maximum range: 24 hours

Export Options:
  --export-file: Specify custom output file
  --export-format: Specify format (text or json)

Examples:
  # Last N minutes/hours with default output
  cloudtrail-logs kms --key your-key-id --last-n 30m

  # Export to custom file
  cloudtrail-logs kms --key your-key-id --last-n 2h --export-file ./my-events.log

  # Export as JSON
  cloudtrail-logs kms --key your-key-id --last-n 2h --export-file ./events.json --export-format json`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate AWS profile
			profile, _ := cmd.Flags().GetString("profile")
			if err := aws.ValidateProfile(profile); err != nil {
				fmt.Println("Error: Invalid AWS profile")
				aws.PrintAWSProfiles()
				return err
			}

			// Validate time range
			_, _, err := timeutil.ValidateAndParseTimeRange(lastN, startTime, endTime)
			if err != nil {
				return fmt.Errorf("invalid time range: %v", err)
			}

			// Validate export format
			if exportFormat != "" && exportFormat != "text" && exportFormat != "json" {
				return fmt.Errorf("invalid export format. Use 'text' or 'json'")
			}

			// Create export directory if needed
			if exportFile != "" {
				dir := filepath.Dir(exportFile)
				if err := os.MkdirAll(dir, 0755); err != nil {
					return fmt.Errorf("failed to create export directory: %v", err)
				}
			}

			return nil
		},
		RunE: runKMS,
	}

	kmsCmd.Flags().StringVar(&keyID, "key", "", "KMS key ID or ARN to monitor")
	kmsCmd.Flags().StringVar(&lastN, "last-n", "", "Look back time (e.g., 5m, 2h)")
	kmsCmd.Flags().StringVar(&startTime, "start", "", "Start time")
	kmsCmd.Flags().StringVar(&endTime, "end", "", "End time")
	kmsCmd.Flags().StringVar(&exportFile, "export-file", "", "Export to specific file")
	kmsCmd.Flags().StringVar(&exportFormat, "export-format", "text", "Export format (text or json)")

	kmsCmd.MarkFlagRequired("key")

	return kmsCmd
}

func runKMS(cmd *cobra.Command, args []string) error {
	start, end, err := timeutil.ValidateAndParseTimeRange(lastN, startTime, endTime)
	if err != nil {
		return err
	}

	fmt.Printf("Time Range: %s (%s)\n",
		timeutil.FormatDuration(end.Sub(start)),
		fmt.Sprintf("%s to %s",
			start.Format("2006-01-02 15:04:05"),
			end.Format("2006-01-02 15:04:05")))

	ctx := context.Background()
	profile, _ := cmd.Flags().GetString("profile")
	region, _ := cmd.Flags().GetString("region")
	outputDir, _ := cmd.Flags().GetString("output")

	// Check AWS credentials
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		fmt.Println("Warning: AWS credentials environment variables not found")
		fmt.Println("Using AWS profile configuration...")
	}

	// Initialize AWS client
	client, err := aws.NewAWSClient(ctx, profile, region)
	if err != nil {
		return fmt.Errorf("AWS client initialization failed:\n%v", err)
	}

	// Configure export options
	exportOptions := &writer.ExportOptions{
		Filename: exportFile,
		Format:   exportFormat,
	}

	// Initialize monitor with export options
	kmsMonitor := monitor.NewKMSMonitor(client, outputDir, exportOptions)

	// Run monitoring
	err = kmsMonitor.MonitorKMSEvents(ctx, keyID, start, end)
	if err != nil {
		return err
	}

	// Print export information if file was specified
	if exportFile != "" {
		fmt.Printf("\nEvents exported to: %s\n", exportFile)
		fmt.Printf("Format: %s\n", exportFormat)
	}

	return nil
}