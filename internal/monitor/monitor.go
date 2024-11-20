// internal/monitor/monitor.go
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/dhairya13703/cloudtrail-logs/internal/aws"
	"github.com/dhairya13703/cloudtrail-logs/internal/writer"
	"github.com/fatih/color"
)

type Monitor struct {
	client    *aws.AWSClient
	logWriter *writer.LogWriter
	mu        sync.Mutex
}

func NewKMSMonitor(client *aws.AWSClient, outputDir string, exportOptions *writer.ExportOptions) *Monitor {
	return &Monitor{
		client:    client,
		logWriter: writer.NewLogWriter(outputDir, "kms", exportOptions),
	}
}

func isKMSEvent(event types.Event, keyID string) bool {
	if event.EventSource != nil && *event.EventSource == "kms.amazonaws.com" {
		// Check resources first
		if event.Resources != nil {
			for _, resource := range event.Resources {
				if resource.ResourceType != nil && resource.ResourceName != nil {
					if *resource.ResourceType == "AWS::KMS::Key" && strings.Contains(*resource.ResourceName, keyID) {
						return true
					}
				}
			}
		}

		// Check CloudTrail event details
		if event.CloudTrailEvent != nil {
			var eventDetails map[string]interface{}
			if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventDetails); err == nil {
				if reqParams, ok := eventDetails["requestParameters"].(map[string]interface{}); ok {
					if keyArn, exists := reqParams["keyId"].(string); exists && strings.Contains(keyArn, keyID) {
						return true
					}
				}
			}
		}
	}
	return false
}

func getResourceInfo(resource types.Resource) string {
	return fmt.Sprintf("%s (%s)", SafeString(resource.ResourceName), SafeString(resource.ResourceType))
}

func SafeString(s *string) string {
	if s == nil {
		return "N/A"
	}
	return *s
}

func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("\nMemory Usage:\n")
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func (m *Monitor) processEvent(event types.Event, keyID string, eventColor, warningColor func(a ...interface{}) string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Basic validation
	if event.EventName == nil || event.EventTime == nil {
		return fmt.Errorf("invalid event: missing required fields")
	}

	var eventDetails map[string]interface{}
	if event.CloudTrailEvent != nil {
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventDetails); err != nil {
			fmt.Printf(warningColor("Warning: Failed to parse event details: %v\n"), err)
		}
	}

	// Write to log file
	if err := m.logWriter.WriteEvent(event, eventDetails); err != nil {
		fmt.Printf(warningColor("Warning: Failed to write to log file: %v\n"), err)
	}

	// Console output
	timeStr := event.EventTime.Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s\n", timeStr, eventColor(*event.EventName))
	fmt.Printf("  User: %s\n", SafeString(event.Username))

	if len(event.Resources) > 0 {
		fmt.Println("  Resources:")
		for _, resource := range event.Resources {
			resourceInfo := getResourceInfo(resource)
			if resource.ResourceName != nil && strings.Contains(*resource.ResourceName, keyID) {
				fmt.Printf("    - %s (Target Key)\n", resourceInfo)
			} else {
				fmt.Printf("    - %s\n", resourceInfo)
			}
		}
	}

	// Print event details
	if eventDetails != nil {
		// Print request parameters
		if reqParams, ok := eventDetails["requestParameters"].(map[string]interface{}); ok && len(reqParams) > 0 {
			fmt.Println("  Request Parameters:")
			for key, value := range reqParams {
				if value != nil {
					fmt.Printf("    %s: %v\n", key, value)
				}
			}
		}

		// Print response elements
		if respElements, ok := eventDetails["responseElements"].(map[string]interface{}); ok && len(respElements) > 0 {
			fmt.Println("  Response Elements:")
			for key, value := range respElements {
				if value != nil {
					fmt.Printf("    %s: %v\n", key, value)
				}
			}
		}
	}

	fmt.Println(strings.Repeat("-", 80))
	return nil
}

func (m *Monitor) MonitorKMSEvents(ctx context.Context, keyID string, start, end time.Time) error {
	eventColor := color.New(color.FgGreen).SprintFunc()
	warningColor := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("Looking up KMS events for key: %s\n", keyID)
	fmt.Printf("Time range: %s to %s\n", start.Format("2006-01-02 15:04:05"), end.Format("2006-01-02 15:04:05"))
	
	logFile := m.logWriter.GetCurrentFile()
	fmt.Printf("Output directory: %s\n", logFile)
	fmt.Println(strings.Repeat("-", 80))

	// Print initial memory usage
	printMemUsage()

	input := &cloudtrail.LookupEventsInput{
		StartTime: &start,
		EndTime:   &end,
	}

	paginator := cloudtrail.NewLookupEventsPaginator(m.client.CloudTrail, input)
	eventCount := 0
	pageCount := 0

	for paginator.HasMorePages() {
		pageCount++
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("error looking up events: %v", err)
		}

		for _, event := range output.Events {
			if !isKMSEvent(event, keyID) {
				continue
			}

			eventCount++
			if err := m.processEvent(event, keyID, eventColor, warningColor); err != nil {
				fmt.Printf(warningColor("Warning: Failed to process event: %v\n"), err)
			}

			// Trigger GC every 100 events
			if eventCount%100 == 0 {
				runtime.GC()
			}
		}

		// Print memory usage every 5 pages
		if pageCount%5 == 0 {
			printMemUsage()
		}
	}

	// Print final memory usage
	printMemUsage()

	if eventCount == 0 {
		fmt.Println(warningColor("\nNo KMS events found for the specified key in the given time range"))
	} else {
		fmt.Printf("\nFound %d KMS events for the specified key\n", eventCount)
	}
	return nil
}