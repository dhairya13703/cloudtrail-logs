// cmd/kms/kms.go
package kms

import (
	"context"
	"fmt"

	"github.com/dhairya13703/cloudtrail-logs/internal/aws"
	"github.com/dhairya13703/cloudtrail-logs/internal/monitor"
	"github.com/dhairya13703/cloudtrail-logs/internal/timeutil"
	"github.com/dhairya13703/cloudtrail-logs/internal/writer"
	"github.com/spf13/cobra"
)

var (
	// Key identifier (optional)
	keyID string

	// Time filters
	lastN     string
	startTime string
	endTime   string

	// Event filters
	eventName   string
	userName    string
	operation   string
	errorsOnly  bool
	successOnly bool

	// Export options
	exportFile   string
	exportFormat string
)

func NewKMSCmd() *cobra.Command {
	kmsCmd := &cobra.Command{
		Use:   "kms",
		Short: "Monitor KMS events",
		Long: `Monitor AWS KMS key usage and events through CloudTrail logs.
        
Search Options:
  --key          Optional: Filter by specific KMS key ID or ARN
  --event        Filter by event name (e.g., "Decrypt", "GenerateDataKey")
  --user         Filter by username
  --operation    Filter by operation type

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

Filter Options:
  --errors-only  Show only error events
  --success-only Show only successful events

Export Options:
  --export-file    Export to specific file
  --export-format  Export format (text or json)

Examples:
  # Search all Decrypt operations
  cloudtrail-logs kms --last-n 30m --event Decrypt

  # Search by specific user
  cloudtrail-logs kms --last-n 1h --user admin --errors-only

  # Search specific KMS key
  cloudtrail-logs kms --key your-key-id --last-n 2h --operation GenerateDataKey

  # Search all KMS operations by a user
  cloudtrail-logs kms --user admin --last-n 1h --export-file user-activity.json`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate time range is provided
			if lastN == "" && (startTime == "" || endTime == "") {
				return fmt.Errorf("time range is required: use either --last-n or both --start and --end")
			}

			// Validate at least one search criteria is provided
			if keyID == "" && eventName == "" && userName == "" && operation == "" {
				return fmt.Errorf("at least one search criteria is required: --key, --event, --user, or --operation")
			}

			if errorsOnly && successOnly {
				return fmt.Errorf("cannot use both --errors-only and --success-only")
			}

			return nil
		},
		RunE: runKMS,
	}

	// Search flags
	kmsCmd.Flags().StringVar(&keyID, "key", "", "Optional: Filter by KMS key ID or ARN")
	kmsCmd.Flags().StringVar(&eventName, "event", "", "Filter by event name")
	kmsCmd.Flags().StringVar(&userName, "user", "", "Filter by username")
	kmsCmd.Flags().StringVar(&operation, "operation", "", "Filter by operation type")

	// Time range flags
	kmsCmd.Flags().StringVar(&lastN, "last-n", "", "Look back time (e.g., 5m, 2h)")
	kmsCmd.Flags().StringVar(&startTime, "start", "", "Start time")
	kmsCmd.Flags().StringVar(&endTime, "end", "", "End time")

	// Filter flags
	kmsCmd.Flags().BoolVar(&errorsOnly, "errors-only", false, "Show only error events")
	kmsCmd.Flags().BoolVar(&successOnly, "success-only", false, "Show only successful events")

	// Export flags
	kmsCmd.Flags().StringVar(&exportFile, "export-file", "", "Export to specific file")
	kmsCmd.Flags().StringVar(&exportFormat, "export-format", "text", "Export format (text or json)")

	return kmsCmd
}

func runKMS(cmd *cobra.Command, args []string) error {
	start, end, err := timeutil.ValidateAndParseTimeRange(lastN, startTime, endTime)
	if err != nil {
		return err
	}

	ctx := context.Background()
	profile, _ := cmd.Flags().GetString("profile")
	region, _ := cmd.Flags().GetString("region")
	outputDir, _ := cmd.Flags().GetString("output")

	// Initialize AWS client
	client, err := aws.NewAWSClient(ctx, profile, region)
	if err != nil {
		return fmt.Errorf("AWS client initialization failed:\n%v", err)
	}

	// Create filter options
	filters := monitor.FilterOptions{
		KeyID:       keyID,
		EventName:   eventName,
		UserName:    userName,
		Operation:   operation,
		ErrorsOnly:  errorsOnly,
		SuccessOnly: successOnly,
	}

	// Create export options
	exportOptions := &writer.ExportOptions{
		Filename: exportFile,
		Format:   exportFormat,
	}

	// Initialize monitor
	kmsMonitor := monitor.NewKMSMonitor(client, outputDir, exportOptions)

	// Run monitoring with filters
	return kmsMonitor.MonitorKMSEvents(ctx, filters, start, end)
}
