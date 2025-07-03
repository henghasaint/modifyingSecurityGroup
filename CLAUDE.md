# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based security group management tool specifically designed for Tencent Cloud. It automatically updates security group rules with dynamic IP addresses, primarily for maintaining office IP whitelists in cloud security groups.

## Core Architecture

The application consists of:
- **main.go**: Single-file Go application containing all core logic
- **config.toml**: TOML configuration file defining credentials and security group settings
- **Cross-platform executables**: Builds for Linux, Windows, and macOS
- **Scheduled execution**: Designed to run via cron (Linux) or Windows Task Scheduler

## Key Components

### IP Discovery System
- Uses multiple HTTP services to discover current public IP addresses
- Implements concurrent IP fetching with goroutines and channels
- Falls back to `http://inip.in/ipinfo.html` for the final required IP
- Supports manual IP specification via file input

### Security Group Management
- Integrates with Tencent Cloud VPC API using official SDK
- Updates security group rules by replacing existing entries at specific indices
- Handles API versioning and rate limiting
- Supports multiple cloud accounts and security groups

### Configuration Structure
- `[[creds]]`: Tencent Cloud credentials (SecretID, SecretKey, SecurityGroups)
- `[[securityGroups]]`: Security group definitions (id, region, ports, protocol, action, description)
- `[dingtalk]`: Optional DingTalk webhook for notifications

## Development Commands

### Build Process
```bash
# Update dependencies
go mod tidy

# Create vendor directory
go mod vendor

# Build for different platforms
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o modifyingSecurityGroup_linux main.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o modifyingSecurityGroup.exe main.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o modifyingSecurityGroup_mac main.go
```

### Runtime Commands
```bash
# Run with automatic IP discovery
./modifyingSecurityGroup_linux --requiredIPs 3

# Run with manual IP file
./modifyingSecurityGroup_linux --ip myips.txt

# Available parameters:
# --ip: Path to file containing IP addresses
# --maxAttempts: Maximum concurrent attempts for IP discovery (default: 35)
# --requiredIPs: Number of unique IPs required (default: 3)
```

## Important Security Considerations

This tool is designed for **defensive security purposes only**:
- Manages IP whitelists for legitimate office access
- Updates security group rules to maintain authorized access
- Includes proper authentication and API versioning
- Logs all operations for audit purposes

## Configuration Requirements

Before running, ensure:
1. Valid Tencent Cloud credentials are configured in `config.toml`
2. Security groups exist and have sufficient pre-configured rules
3. The number of `--requiredIPs` matches the number of pre-configured rules in each security group
4. Network access to IP discovery services and Tencent Cloud API endpoints

## File Structure

- `config.toml-example`: Template configuration file
- `config.toml-test`: Test configuration
- `modifyingSG.bat`: Windows batch script for scheduled execution
- `ips.txt`: Automatically generated file storing last known IP addresses (for change detection)
- `logs/`: Directory for execution logs (Windows batch script)

## Dependencies

Uses Go modules with key dependencies:
- `github.com/tencentcloud/tencentcloud-sdk-go`: Official Tencent Cloud SDK
- `github.com/spf13/viper`: Configuration management
- `github.com/PuerkitoBio/goquery`: HTML parsing for IP discovery