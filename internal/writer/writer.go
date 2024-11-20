// internal/writer/writer.go
package writer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type LogWriter struct {
	outputDir    string
	serviceTag   string
	customFile   string
	exportMode   string
	mu           sync.Mutex
}

type ExportOptions struct {
	Filename string
	Format   string // text, json
}

func NewLogWriter(outputDir, serviceTag string, options *ExportOptions) *LogWriter {
	writer := &LogWriter{
		outputDir:  outputDir,
		serviceTag: serviceTag,
	}

	if options != nil {
		writer.customFile = options.Filename
		writer.exportMode = options.Format
	}

	// Create output directory if it doesn't exist
	if writer.customFile != "" {
		os.MkdirAll(filepath.Dir(writer.customFile), 0755)
	} else {
		os.MkdirAll(filepath.Join(outputDir, serviceTag), 0755)
	}

	return writer
}

func formatEventAsText(event types.Event, eventDetails map[string]interface{}) string {
	var sb strings.Builder

	// Write timestamp and event name
	sb.WriteString(fmt.Sprintf("[%s] %s\n",
		event.EventTime.Format("2006-01-02 15:04:05"),
		SafeString(event.EventName)))

	// Write source
	sb.WriteString(fmt.Sprintf("Source: %s\n", SafeString(event.EventSource)))

	// Write username
	username := "N/A"
	if event.Username != nil {
		username = *event.Username
	}
	sb.WriteString(fmt.Sprintf("User: %s\n", username))

	// Write resources
	if len(event.Resources) > 0 {
		sb.WriteString("Resources:\n")
		for _, resource := range event.Resources {
			sb.WriteString(fmt.Sprintf("  - %s (%s)\n",
				SafeString(resource.ResourceName),
				SafeString(resource.ResourceType)))
		}
	}

	// Write event details
	if eventDetails != nil {
		sb.WriteString("Details:\n")
		// Request Parameters
		if reqParams, ok := eventDetails["requestParameters"].(map[string]interface{}); ok && len(reqParams) > 0 {
			sb.WriteString("  Request Parameters:\n")
			for key, value := range reqParams {
				if value != nil {
					sb.WriteString(fmt.Sprintf("    %s: %v\n", key, value))
				}
			}
		}

		// Response Elements
		if respElements, ok := eventDetails["responseElements"].(map[string]interface{}); ok && len(respElements) > 0 {
			sb.WriteString("  Response Elements:\n")
			for key, value := range respElements {
				if value != nil {
					sb.WriteString(fmt.Sprintf("    %s: %v\n", key, value))
				}
			}
		}
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")
	return sb.String()
}

func SafeString(s *string) string {
	if s == nil {
		return "N/A"
	}
	return *s
}

func (w *LogWriter) WriteEvent(event types.Event, eventDetails map[string]interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var filename string
	if w.customFile != "" {
		filename = w.customFile
	} else {
		filename = filepath.Join(
			w.outputDir,
			w.serviceTag,
			fmt.Sprintf("%s-events-%s.log", w.serviceTag, time.Now().Format("2006-01-02")),
		)
	}

	// Open file in append mode
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer f.Close()

	var content string
	switch w.exportMode {
	case "json":
		jsonData := map[string]interface{}{
			"timestamp":     event.EventTime.Format("2006-01-02 15:04:05"),
			"eventName":     SafeString(event.EventName),
			"eventSource":   SafeString(event.EventSource),
			"user":         SafeString(event.Username),
			"resources":     event.Resources,
			"details":      eventDetails,
		}
		jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		content = string(jsonBytes) + "\n"
	default: // text format
		content = formatEventAsText(event, eventDetails)
	}

	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to log file: %v", err)
	}

	return nil
}

func (w *LogWriter) GetCurrentFile() string {
	if w.customFile != "" {
		return w.customFile
	}
	return filepath.Join(
		w.outputDir,
		w.serviceTag,
		fmt.Sprintf("%s-events-%s.log", w.serviceTag, time.Now().Format("2006-01-02")),
	)
}