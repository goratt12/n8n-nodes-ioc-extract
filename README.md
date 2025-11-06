# n8n-nodes-ioc-extract

This is an n8n community node that extracts Indicators of Compromise (IOCs) from text using regex-based pattern matching. It can identify various types of security indicators including hashes, IP addresses, URLs, domains, and email addresses.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/sustainable-use-license/) workflow automation platform.

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

## Features

The IOC Extract node can extract the following types of Indicators of Compromise:

### Hashes
- **MD5**: 32-character hexadecimal hashes
- **SHA1**: 40-character hexadecimal hashes
- **SHA256**: 64-character hexadecimal hashes

### Network Indicators
- **IPv4 addresses**: Standard IPv4 format (e.g., 192.168.1.1)
- **IPv6 addresses**: Standard IPv6 format including compressed notation
- **URLs**: HTTP and HTTPS URLs
- **Domains**: Domain names (excluding those already found in URLs or emails)
- **Email addresses**: Standard email format

### Defang/Refang Support
- **Refang Input**: Automatically converts defanged IOCs in input text to normal format for extraction
  - Handles patterns like: `[.]`, `(.)`, `[@]`, `[://]`, `hxxp`, `hxxps`, `[dot]`, `[at]`, `[1]`, `(1)`, etc.
- **Defang Output**: Converts extracted IOCs to defanged format in the output
  - Converts: `.` → `[.]`, `@` → `[@]`, `://` → `[://]`

## Operations

The node has one operation that extracts IOCs from input text:

- **Extract IOCs**: Analyzes the input text and extracts all detected IOCs

## Configuration Options

### Input Text
- **Required**: Yes
- **Description**: The text from which to extract Indicators of Compromise

### Output Mode
- **Options**:
  - **Single Item**: Outputs all IOCs in a single item with nested structure
  - **Each IOC as Item**: Outputs each IOC as a separate item with `value`, `type` (singular), and `category` (singular) attributes
- **Default**: Single Item

### Refang Input
- **Type**: Boolean
- **Default**: false
- **Description**: If enabled, refangs defanged IOCs in input text before extraction (e.g., `example[.]com` → `example.com`)

### Defang Output
- **Type**: Boolean
- **Default**: false
- **Description**: If enabled, defangs extracted IOCs in output (e.g., `example.com` → `example[.]com`)

## Credentials

No credentials are required for this node.

## Compatibility

This node is compatible with n8n version 1.0 and later. It uses regex-based extraction and has no external dependencies.

## Usage

### Example 1: Basic IOC Extraction

Input text:
```
Contact us at admin@example.com or visit https://malicious-site.com/path
The file hash is 5d41402abc4b2a76b9719d911017c592
```

Output (Single Item mode):
```json
{
  "iocs": {
    "hashes": {
      "md5s": ["5d41402abc4b2a76b9719d911017c592"],
      "sha1s": [],
      "sha256s": []
    },
    "networks": {
      "ipv4s": [],
      "ipv6s": [],
      "urls": ["https://malicious-site.com/path"],
      "domains": ["example.com"],
      "emails": ["admin@example.com"]
    }
  }
}
```

### Example 2: Handling Defanged IOCs

Input text:
```
Visit example[.]com or contact user[@]example[.]com
IP address: 192.168.1.[1]
```

With "Refang Input" enabled, the node will:
1. Convert `example[.]com` → `example.com`
2. Convert `user[@]example[.]com` → `user@example.com`
3. Convert `192.168.1.[1]` → `192.168.1.1`
4. Extract the IOCs from the refanged text

### Example 3: Individual Item Output

With "Each IOC as Item" mode enabled, each IOC is output as a separate item:

```json
[
  {
    "value": "admin@example.com",
    "type": "email",
    "category": "network"
  },
  {
    "value": "https://malicious-site.com/path",
    "type": "url",
    "category": "network"
  },
  {
    "value": "5d41402abc4b2a76b9719d911017c592",
    "type": "md5",
    "category": "hash"
  }
]
```

## Resources

* [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
* [n8n documentation](https://docs.n8n.io/)

## Version history

### Version 1.0.0
- Initial release
- Regex-based IOC extraction for hashes (MD5, SHA1, SHA256), IP addresses (IPv4, IPv6), URLs, domains, and emails
- Support for defang/refang operations
- Single item and individual item output modes
