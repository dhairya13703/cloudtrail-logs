# CloudTrail Log Analyzer

A powerful command-line tool for analyzing AWS CloudTrail logs with advanced filtering and search capabilities.

## Features

- Real-time CloudTrail log monitoring
- Multiple search criteria support
- Flexible time range options
- Export capabilities (Text/JSON)
- Memory-efficient processing
- Color-coded output for better visibility
- Concurrent log processing

## Installation
[Installation](INSTALL.md)

## Usage

### Basic Command Structure
```bash
ctmon kms [flags]
```

### Time Range Options

1. **Relative Time**
```bash
# Last 30 minutes
--last-n 30m

# Last 2 hours
--last-n 2h

Available ranges: 1m to 24h
```

2. **Custom Time Range**
```bash
--start "2024-11-20 10:00:00" --end "2024-11-20 11:00:00"

Formats supported:
- YYYY-MM-DD HH:mm:ss
- YYYY-MM-DD HH:mm
- YYYY-MM-DD (uses full day)
```

### Search Options

1. **KMS Key (Optional)**
```bash
--key "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
```

2. **Event Name**
```bash
--event Decrypt
--event GenerateDataKey
```

3. **User**
```bash
--user admin
```

4. **Operation**
```bash
--operation GenerateDataKey
```

### Filter Options

```bash
# Show only errors
--errors-only

# Show only successful operations
--success-only
```

### Export Options

```bash
# Export to file
--export-file output.log

# Export format (text/json)
--export-format json
```

### AWS Profile and Region

```bash
--profile your-profile-name
--region us-east-1
```

## Example Commands

### 1. Search for Decrypt Operations
```bash
ctmon kms \
  --last-n 1h \
  --event Decrypt \
  --user admin \
  --errors-only \
  --export-file decrypt-errors.json \
  --profile prod
```

### 2. Monitor Key Generation Events
```bash
ctmon kms \
  --last-n 30m \
  --operation GenerateDataKey \
  --success-only \
  --export-file key-generation.json \
  --profile dev
```

### 3. Search Specific KMS Key Usage
```bash
ctmon kms \
  --key arn:aws:kms:us-east-1:123456789012:key/abcd-1234 \
  --last-n 2h \
  --export-format json \
  --profile prod
```

### 4. Monitor User Activity
```bash
ctmon kms \
  --user admin \
  --last-n 1h \
  --export-file user-activity.json \
  --profile prod
```

### 5. Custom Time Range Search
```bash
ctmon kms \
  --start "2024-11-20 10:00" \
  --end "2024-11-20 11:00" \
  --operation GenerateDataKey \
  --success-only \
  --export-format json \
  --profile prod
```

## Output Format

### Console Output
```plaintext
Active Filters:
- Event Name: Decrypt
- User: admin
- Showing only errors

Time range: 2024-11-20 13:00:00 to 2024-11-20 14:00:00
Output file: /path/to/output/errors.json
--------------------------------------------------------------------------------
[2024-11-20 13:15:23] Decrypt
  User: admin
  Resources:
    - arn:aws:kms:us-east-1:123456789012:key/abcd-1234 (AWS::KMS::Key)
  Request Parameters:
    keyId: arn:aws:kms:us-east-1:123456789012:key/abcd-1234
  Error: AccessDenied - User not authorized to perform operation
--------------------------------------------------------------------------------
```

### JSON Export Format
```json
{
  "timestamp": "2024-11-20 13:15:23",
  "eventName": "Decrypt",
  "eventSource": "kms.amazonaws.com",
  "user": "admin",
  "resources": [
    {
      "resourceName": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
      "resourceType": "AWS::KMS::Key"
    }
  ],
  "details": {
    "errorCode": "AccessDenied",
    "errorMessage": "User not authorized to perform operation",
    "requestParameters": {
      "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
    }
  }
}
```

## Memory Usage

The tool includes built-in memory monitoring:
```plaintext
Memory Usage:
Alloc = 5 MiB    TotalAlloc = 10 MiB    Sys = 20 MiB    NumGC = 2
```

## Error Handling

- Validates AWS credentials and profiles
- Reports detailed error messages
- Continues processing on non-fatal errors
- Provides warnings for potential issues

## Limitations

- Maximum time range: 24 hours
- Requires appropriate AWS permissions
- Rate limited by AWS CloudTrail API

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)