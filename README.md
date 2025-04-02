# SSL Handshake Tool

A Go-based utility for analyzing SSL/TLS connections, certificate chains, and cipher suites.

## Overview

This tool helps troubleshoot and analyze SSL/TLS connections by:
- Validating DNS resolution
- Testing TCP connectivity
- Establishing SSL/TLS sessions
- Examining certificate chains
- Analyzing supported TLS versions and cipher suites

## Features

- Direct SSL/TLS connections to servers
- Connections via forward proxies (with optional authentication)
- Certificate chain validation and display
- Verbose output for TLS version and cipher suite detection
- DNS resolution validation
- TCP connection testing
- Support for custom certificate files as trust stores

## Installation

### Prerequisites
- Go 1.15 or later

### Build Instructions
```bash
go build -o ssl_handshake *.go
```

## Usage

### Basic Usage
```bash
./ssl_handshake -sslserver example.com:443
```

### With Forward Proxy
```bash
./ssl_handshake -sslserver example.com:443 -proxy proxy.example.com:8080
```

### With Forward Proxy and Authentication
```bash
./ssl_handshake -sslserver example.com:443 -proxy proxy.example.com:8080 -proxyAuth username:password
```

### With Custom Certificate File
```bash
./ssl_handshake -sslserver example.com:443 -certFile /path/to/certificate.pem
```

### Additional Options
- `-v`: Enable verbose output for detailed TLS information
- `-useIP`: Test connections to each resolved IP address (requires `-v`)
- `-h` or `-help`: Display usage information

## Command-Line Arguments

| Argument | Description | Required/Optional |
|----------|-------------|-------------------|
| `-sslserver` | Server hostname and port (e.g., example.com:443) | Required |
| `-proxy` | Forward proxy hostname and port | Optional |
| `-proxyAuth` | Proxy authentication credentials (username:password) | Optional |
| `-certFile` | Path to PEM certificate file to use as trust store | Optional |
| `-v` | Enable verbose output | Optional |
| `-useIP` | Connect to each resolved IP address | Optional |
| `-h`, `-help` | Display help information | Optional |

## Output Information

The tool provides detailed information about:
1. DNS resolution for server and proxy hosts
2. TCP connectivity to resolved IP addresses
3. TLS handshake details including:
   - Server address
   - TLS version
   - Negotiated cipher suite
   - Certificate chain details
4. Supported TLS versions and cipher suites (with `-v` option)
5. Certificate details in PEM format

## Examples

### Basic SSL Analysis
```bash
./ssl_handshake -sslserver google.com:443
```

### Detailed Analysis with Verbose Output
```bash
./ssl_handshake -sslserver google.com:443 -v
```

### Analysis Through Corporate Proxy
```bash
./ssl_handshake -sslserver internal-service.company.com:443 -proxy corporate-proxy.company.com:8080 -proxyAuth username:password -certFile company-ca.pem
```

## Notes

- The tool will fail if it cannot establish TCP connections to the target server
- When using a proxy, the tool verifies connectivity to both the proxy and target server
- Certificate validation can be performed using a custom certificate file
- The verbose mode provides detailed information about supported TLS versions and cipher suites
