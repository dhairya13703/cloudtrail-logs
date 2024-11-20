# Installation Instructions

Choose the instructions for your operating system and architecture.

## Linux

### For x86_64 (AMD64)
```bash
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Linux_x86_64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# Or if you don't have sudo access:
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Linux_x86_64 | cut -d '"' -f 4) | tar xz && mkdir -p ~/bin && mv cloudtrail-logs ~/bin/
```

### For ARM64
```bash
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Linux_arm64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# Or if you don't have sudo access:
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Linux_arm64 | cut -d '"' -f 4) | tar xz && mkdir -p ~/bin && mv cloudtrail-logs ~/bin/
```

## macOS

### For Intel Macs (x86_64)
```bash
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_x86_64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# Or if you don't have sudo access:
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_x86_64 | cut -d '"' -f 4) | tar xz && mkdir -p ~/bin && mv cloudtrail-logs ~/bin/
```

### For Apple Silicon (M1/M2, ARM64)
```bash
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_arm64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# Or if you don't have sudo access:
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_arm64 | cut -d '"' -f 4) | tar xz && mkdir -p ~/bin && mv cloudtrail-logs ~/bin/
```

## Windows

### For x86_64 (64-bit)

Using PowerShell:
```powershell
# Download latest release
$release_url = (Invoke-RestMethod -Uri "https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest").assets | Where-Object { $_.name -like "*Windows_x86_64.zip" } | Select-Object -ExpandProperty browser_download_url
Invoke-WebRequest -Uri $release_url -OutFile "cloudtrail-logs.zip"

# Extract
Expand-Archive -Path "cloudtrail-logs.zip" -DestinationPath "C:\Program Files\cloudtrail-logs"

# Add to PATH (requires admin PowerShell)
$env:Path += ";C:\Program Files\cloudtrail-logs"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
```

Or manually:
1. Get the latest release URL:
```bash
curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Windows_x86_64.zip
```
2. Download the displayed URL
3. Extract the zip file
4. Add the extracted directory to your PATH

## Quick Install Script (Linux/macOS)

For a quick one-line installation:
```bash
# For Linux x86_64
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Linux_x86_64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# For macOS Intel
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_x86_64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/

# For macOS Apple Silicon
curl -L $(curl -s https://api.github.com/repos/dhairya13703/cloudtrail-logs/releases/latest | grep browser_download_url | grep Darwin_arm64 | cut -d '"' -f 4) | tar xz && sudo mv cloudtrail-logs /usr/local/bin/
```

## Verify Installation

After installation, verify it works:
```bash
cloudtrail-logs --help
```

## Troubleshooting

1. If you get "permission denied" errors on Linux/macOS:
```bash
chmod +x cloudtrail-logs
```

2. If you get "command not found" after installation:
   - Make sure the binary is in your PATH
   - Try restarting your terminal
   - Run `which cloudtrail-logs` to verify installation location

3. If you get API rate limit errors:
   - Use a GitHub token: `export GITHUB_TOKEN=your_token`
   - Or manually download from the [releases page](../../releases/latest)

4. If you get SSL/TLS errors during download:
   - Try using `wget` instead of `curl`
   - Check your system's SSL certificates
   - Use the manual download from the releases page

For more help, please [open an issue](../../issues)

## Manual Download Links

Visit the [latest release page](../../releases/latest) and download the appropriate file for your system:

| OS      | Architecture | File Pattern |
|---------|-------------|--------------|
| Linux   | x86_64      | cloudtrail-logs_Linux_x86_64.tar.gz |
| Linux   | ARM64       | cloudtrail-logs_Linux_arm64.tar.gz |
| macOS   | x86_64      | cloudtrail-logs_Darwin_x86_64.tar.gz |
| macOS   | ARM64       | cloudtrail-logs_Darwin_arm64.tar.gz |
| Windows | x86_64      | cloudtrail-logs_Windows_x86_64.zip |