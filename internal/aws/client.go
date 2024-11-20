// internal/aws/client.go
package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSClient struct {
	CloudTrail *cloudtrail.Client
	Region     string
	Profile    string
}

func NewAWSClient(ctx context.Context, profile, region string) (*AWSClient, error) {
	// First validate if the profile exists
	if err := ValidateProfile(profile); err != nil {
		fmt.Printf("\nError: %v\n", err)
		PrintAWSProfiles()
		return nil, fmt.Errorf("invalid AWS profile: %s", profile)
	}

	fmt.Printf("Attempting to load AWS profile: %s\n", profile)

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(profile),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v\nPlease check your AWS credentials and profile configuration", err)
	}

	// Verify credentials by making a test call to STS
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("\nFailed to authenticate with profile '%s'\n", profile)
		PrintAWSProfiles()
		return nil, fmt.Errorf("failed to verify AWS credentials: %v\n\nPossible solutions:\n"+
			"1. Run 'aws configure' to set up your credentials\n"+
			"2. Check if the profile '%s' exists in ~/.aws/credentials\n"+
			"3. Ensure your credentials are not expired\n", 
			err, profile)
	}

	// Print identity information
	fmt.Printf("\nAWS Authentication Successful:\n")
	fmt.Printf("Account: %s\n", *identity.Account)
	fmt.Printf("User ID: %s\n", *identity.UserId)
	fmt.Printf("ARN: %s\n", *identity.Arn)
	fmt.Printf("Using Profile: %s\n", profile)
	fmt.Printf("Region: %s\n", region)
	fmt.Println(strings.Repeat("-", 80))

	return &AWSClient{
		CloudTrail: cloudtrail.NewFromConfig(cfg),
		Region:     region,
		Profile:    profile,
	}, nil
}

// PrintAWSProfiles prints all available AWS profiles from the credentials file
func PrintAWSProfiles() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory")
		return
	}

	credentialsPath := filepath.Join(homeDir, ".aws", "credentials")
	configPath := filepath.Join(homeDir, ".aws", "config")

	fmt.Println("\nAvailable AWS Profiles:")

	// Check credentials file
	if _, err := os.Stat(credentialsPath); err == nil {
		fmt.Println("\nFrom ~/.aws/credentials:")
		if content, err := os.ReadFile(credentialsPath); err == nil {
			profiles := extractProfiles(string(content), false)
			for _, p := range profiles {
				fmt.Printf("  - %s\n", p)
			}
		}
	}

	// Check config file
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("\nFrom ~/.aws/config:")
		if content, err := os.ReadFile(configPath); err == nil {
			profiles := extractProfiles(string(content), true)
			for _, p := range profiles {
				fmt.Printf("  - %s\n", p)
			}
		}
	}

	fmt.Println("\nTo use a specific profile, run the command with --profile flag:")
	fmt.Println("Example: go run main.go kms --profile your-profile-name --key your-key-id")
	fmt.Println()
}

// extractProfiles extracts profile names from AWS credential/config files
func extractProfiles(content string, isConfig bool) []string {
	var profiles []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			profile := line[1 : len(line)-1]
			if isConfig {
				// Remove "profile " prefix if present
				profile = strings.TrimPrefix(profile, "profile ")
			}
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

// ValidateProfile checks if an AWS profile exists
func ValidateProfile(profile string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	credentialsPath := filepath.Join(homeDir, ".aws", "credentials")
	configPath := filepath.Join(homeDir, ".aws", "config")

	// Check if either file exists
	credentialsExists := false
	configExists := false

	if _, err := os.Stat(credentialsPath); err == nil {
		credentialsExists = true
	}
	if _, err := os.Stat(configPath); err == nil {
		configExists = true
	}

	if !credentialsExists && !configExists {
		return fmt.Errorf("no AWS credentials found. Run 'aws configure' to set up your credentials")
	}

	// Read credentials file
	if credentialsExists {
		if content, err := os.ReadFile(credentialsPath); err == nil {
			if strings.Contains(string(content), fmt.Sprintf("[%s]", profile)) {
				return nil
			}
		}
	}

	// Read config file
	if configExists {
		if content, err := os.ReadFile(configPath); err == nil {
			if strings.Contains(string(content), fmt.Sprintf("[profile %s]", profile)) {
				return nil
			}
		}
	}

	return fmt.Errorf("profile '%s' not found in AWS credentials or config files", profile)
}