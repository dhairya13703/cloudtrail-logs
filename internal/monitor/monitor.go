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

func (m *Monitor) MonitorKMSEvents(ctx context.Context, filters FilterOptions, start, end time.Time) error {
	eventColor := color.New(color.FgGreen).SprintFunc()
	warningColor := color.New(color.FgYellow).SprintFunc()
	errorColor := color.New(color.FgRed).SprintFunc()

	// Print active filters
	fmt.Println("Active Filters:")
	if filters.KeyID != "" {
		fmt.Printf("- KMS Key: %s\n", filters.KeyID)
	}
	if filters.EventName != "" {
		fmt.Printf("- Event Name: %s\n", filters.EventName)
	}
	if filters.UserName != "" {
		fmt.Printf("- User: %s\n", filters.UserName)
	}
	if filters.Operation != "" {
		fmt.Printf("- Operation: %s\n", filters.Operation)
	}
	if filters.ErrorsOnly {
		fmt.Println("- Showing only errors")
	}
	if filters.SuccessOnly {
		fmt.Println("- Showing only successful operations")
	}

	fmt.Printf("\nTime range: %s to %s\n",
		start.Format("2006-01-02 15:04:05"),
		end.Format("2006-01-02 15:04:05"))

	logFile := m.logWriter.GetCurrentFile()
	fmt.Printf("Output file: %s\n", logFile)
	fmt.Println(strings.Repeat("-", 80))

	input := &cloudtrail.LookupEventsInput{
		StartTime: &start,
		EndTime:   &end,
	}

	paginator := cloudtrail.NewLookupEventsPaginator(m.client.CloudTrail, input)
	eventCount := 0

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("error looking up events: %v", err)
		}

		for _, event := range output.Events {
			if !matchesFilter(event, filters) {
				continue
			}

			eventCount++

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
			eventName := SafeString(event.EventName)
			username := SafeString(event.Username)

			// Determine if event had an error
			isError := false
			if eventDetails != nil {
				_, isError = eventDetails["errorCode"].(string)
			}

			// Color the event name based on status
			coloredEventName := eventName
			if isError {
				coloredEventName = errorColor(eventName)
			} else {
				coloredEventName = eventColor(eventName)
			}

			fmt.Printf("[%s] %s\n", timeStr, coloredEventName)
			fmt.Printf("  User: %s\n", username)

			if len(event.Resources) > 0 {
				fmt.Println("  Resources:")
				for _, resource := range event.Resources {
					resourceInfo := getResourceInfo(resource)
					if resource.ResourceName != nil && filters.KeyID != "" &&
						strings.Contains(*resource.ResourceName, filters.KeyID) {
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

				// Print errors if present
				if errorCode, ok := eventDetails["errorCode"].(string); ok {
					errorMessage, _ := eventDetails["errorMessage"].(string)
					fmt.Printf(errorColor("  Error: %s - %s\n"), errorCode, errorMessage)
				}
			}

			fmt.Println(strings.Repeat("-", 80))
		}
	}

	if eventCount == 0 {
		fmt.Println(warningColor("\nNo events found matching the specified filters"))
	} else {
		fmt.Printf("\nFound %d matching events\n", eventCount)
	}
	return nil
}

// internal/monitor/monitor.go

type FilterOptions struct {
	KeyID       string
	EventName   string
	UserName    string
	Operation   string
	ErrorsOnly  bool
	SuccessOnly bool
}

func matchesFilter(event types.Event, filters FilterOptions) bool {
	// Always check KMS key if provided
	if filters.KeyID != "" {
		isKMSMatch := false
		// Check in resources
		if event.Resources != nil {
			for _, resource := range event.Resources {
				if resource.ResourceType != nil && resource.ResourceName != nil {
					if *resource.ResourceType == "AWS::KMS::Key" && strings.Contains(*resource.ResourceName, filters.KeyID) {
						isKMSMatch = true
						break
					}
				}
			}
		}

		// Check in event details
		if !isKMSMatch && event.CloudTrailEvent != nil {
			var eventDetails map[string]interface{}
			if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventDetails); err == nil {
				if reqParams, ok := eventDetails["requestParameters"].(map[string]interface{}); ok {
					if keyArn, exists := reqParams["keyId"].(string); exists && strings.Contains(keyArn, filters.KeyID) {
						isKMSMatch = true
					}
				}
			}
		}

		if !isKMSMatch {
			return false
		}
	}

	// Check event name if provided
	if filters.EventName != "" {
		if event.EventName == nil || !strings.Contains(strings.ToLower(*event.EventName), strings.ToLower(filters.EventName)) {
			return false
		}
	}

	// Check username if provided
	if filters.UserName != "" {
		if event.Username == nil || !strings.Contains(strings.ToLower(*event.Username), strings.ToLower(filters.UserName)) {
			return false
		}
	}

	// Check operation if provided
	if filters.Operation != "" {
		if event.EventName == nil || !strings.Contains(*event.EventName, filters.Operation) {
			return false
		}
	}

	// Check for errors/success if requested
	if filters.ErrorsOnly || filters.SuccessOnly {
		var eventDetails map[string]interface{}
		if event.CloudTrailEvent != nil {
			if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventDetails); err == nil {
				errorCode, hasError := eventDetails["errorCode"].(string)
				if filters.ErrorsOnly && !hasError {
					return false
				}
				if filters.SuccessOnly && hasError && errorCode != "" {
					return false
				}
			}
		}
	}

	return true
}
