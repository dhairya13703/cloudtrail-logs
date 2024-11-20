// internal/timeutil/timeutil.go
package timeutil

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TimeRange represents a supported time range format
type TimeRange struct {
	Duration time.Duration
	Display  string
}

// RelativeTimeRange parses and validates a relative time range (e.g., "5m", "2h")
func RelativeTimeRange(timeRange string) (time.Time, time.Time, error) {
	now := time.Now()

	// Regular expression to match number + unit (m for minutes, h for hours)
	re := regexp.MustCompile(`^(\d+)(m|h)$`)
	matches := re.FindStringSubmatch(timeRange)

	if matches == nil {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"invalid time range format. Use: "+
				"\n  - Minutes: e.g., '5m' for last 5 minutes"+
				"\n  - Hours: e.g., '2h' for last 2 hours"+
				"\n  Maximum allowed: 24h")
	}

	value, _ := strconv.Atoi(matches[1])
	unit := matches[2]

	var duration time.Duration
	switch unit {
	case "m":
		if value <= 0 || value > 1440 { // 1440 minutes = 24 hours
			return time.Time{}, time.Time{}, fmt.Errorf("minutes must be between 1 and 1440 (24 hours)")
		}
		duration = time.Duration(value) * time.Minute
	case "h":
		if value <= 0 || value > 24 {
			return time.Time{}, time.Time{}, fmt.Errorf("hours must be between 1 and 24")
		}
		duration = time.Duration(value) * time.Hour
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("unsupported time unit. Use 'm' for minutes or 'h' for hours")
	}

	return now.Add(-duration), now, nil
}

// CustomTimeRange parses custom start and end times
func CustomTimeRange(start, end string) (time.Time, time.Time, error) {
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}

	var startTime, endTime time.Time
	var err error
	startParsed := false
	endParsed := false

	// Try each layout for start time
	for _, layout := range layouts {
		startTime, err = time.Parse(layout, start)
		if err == nil {
			startParsed = true
			break
		}
	}

	if !startParsed {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start time format. Use one of:"+
			"\n  - YYYY-MM-DD HH:mm:ss"+
			"\n  - YYYY-MM-DD HH:mm"+
			"\n  - YYYY-MM-DD")
	}

	// Try each layout for end time
	for _, layout := range layouts {
		endTime, err = time.Parse(layout, end)
		if err == nil {
			endParsed = true
			break
		}
	}

	if !endParsed {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end time format. Use one of:"+
			"\n  - YYYY-MM-DD HH:mm:ss"+
			"\n  - YYYY-MM-DD HH:mm"+
			"\n  - YYYY-MM-DD")
	}

	// If only date was provided, set end time to end of day
	if strings.Contains(end, ":") == false {
		endTime = endTime.Add(23 * time.Hour).Add(59 * time.Minute).Add(59 * time.Second)
	}

	// Validate time range
	duration := endTime.Sub(startTime)
	if duration < 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("end time cannot be before start time")
	}

	if duration > 24*time.Hour {
		return time.Time{}, time.Time{}, fmt.Errorf("time range cannot exceed 24 hours")
	}

	return startTime, endTime, nil
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute

	parts := []string{}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if len(parts) == 0 {
		return "0m"
	}
	return strings.Join(parts, " ")
}

// ValidateAndParseTimeRange handles both relative and custom time ranges
func ValidateAndParseTimeRange(lastN, start, end string) (time.Time, time.Time, error) {
	if lastN != "" {
		if start != "" || end != "" {
			return time.Time{}, time.Time{}, fmt.Errorf("cannot use --last-n with --start/--end flags")
		}
		return RelativeTimeRange(lastN)
	}

	if (start != "" && end == "") || (start == "" && end != "") {
		return time.Time{}, time.Time{}, fmt.Errorf("both --start and --end must be provided together")
	}

	if start == "" && end == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("either --last-n or both --start and --end must be provided")
	}

	return CustomTimeRange(start, end)
}