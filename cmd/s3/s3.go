package s3

import (
	"github.com/dhairya13703/cloudtrail-logs/internal/aws"
	"github.com/dhairya13703/cloudtrail-logs/internal/monitor"
	"github.com/dhairya13703/cloudtrail-logs/internal/timeutil"
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var (
	bucketName string
	timeRange  string
	startTime  string
	endTime    string
	operation  string
)

func NewS3Cmd() *cobra.Command {
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "Monitor S3 events",
		Long: `Monitor AWS S3 bucket activities through CloudTrail logs.
Tracks operations like PutObject, GetObject, DeleteObject, etc.`,
		RunE: runS3,
	}

	// S3-specific flags
	s3Cmd.Flags().StringVar(&bucketName, "bucket", "", "S3 bucket name to monitor")
	s3Cmd.Flags().StringVar(&operation, "operation", "", "S3 operation to filter (e.g., PutObject, GetObject)")
	s3Cmd.Flags().StringVar(&timeRange, "time-range", "", "Time range (1h, 6h, 12h, 1d, 7d, 30d)")
	s3Cmd.Flags().StringVar(&startTime, "start", "", "Start time (format: 2006-01-02 15:04:05)")
	s3Cmd.Flags().StringVar(&endTime, "end", "", "End time (format: 2006-01-02 15:04:05)")

	s3Cmd.MarkFlagRequired("bucket")

	return s3Cmd
}

func runS3(cmd *cobra.Command, args []string) error {
	var start, end time.Time
	var err error

	if timeRange != "" {
		start, end, err = timeutil.ParseTimeRange(timeRange)
	} else if startTime != "" && endTime != "" {
		start, end, err = timeutil.ParseCustomTimeRange(startTime, endTime)
	} else {
		return fmt.Errorf("either --time-range or both --start and --end must be specified")
	}

	if err != nil {
		return err
	}

	ctx := context.Background()
	profile, _ := cmd.Flags().GetString("profile")
	region, _ := cmd.Flags().GetString("region")
	outputDir, _ := cmd.Flags().GetString("output")

	client, err := aws.NewAWSClient(ctx, profile, region)
	if err != nil {
		return err
	}

	monitor := monitor.NewS3Monitor(client, outputDir)
	return monitor.MonitorS3Events(ctx, bucketName, operation, start, end)
}