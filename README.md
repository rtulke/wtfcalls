# WTFCalls

What the Fuck Calls is a robust tool for live monitoring of outgoing network connections.

## Features

- **Live Connection Monitoring**: Detect and display all outgoing network connections in real-time
- **Enhanced TUI Interface**: Advanced textual user interface with filtering and multiple views
- **Security Analysis**: Detect potentially suspicious connections based on configurable rules
- **Traffic Monitoring**: Track data transferred for each connection
- **Export Capabilities**: Export connection data and security alerts in CSV, JSON, or YAML format
- **Compatibility**: Works on both Linux and macOS systems

## Installation

### Prerequisites

Required Python packages:
```bash
pip install psutil rich textual pyyaml ipaddress
```

### Basic Installation

```bash
git clone https://github.com/rtulke/wtfcalls.git
cd wtfcalls
chmod +x wtfcalls.py
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .
```

## Usage

### Basic Usage

Run the basic monitoring interface:

```bash
./wtfcalls.py
```

### Enhanced Usage

Run with additional features:

```bash
./wtfcalls.py --traffic --security --split-port
```

### TUI Interface

Run the enhanced TUI interface:

```bash
./wtfcalls_tui.py
```

### Command Line Options

```
usage: wtfcalls.py [-h] [--ipv4] [--ipv6] [--delay-closed SEC] [--delay-new SEC] [--no-resolve] [--split-port] [--poll-interval SEC] [--full-path]
                  [--traffic] [--security] [--security-config SECURITY_CONFIG] [--export-format {csv,json,yaml}] [--export-file EXPORT_FILE]
                  [--export-alerts EXPORT_ALERTS] [--filter-process FILTER_PROCESS] [--filter-port FILTER_PORT] [--filter-ip FILTER_IP]

wtfcalls: Monitor outgoing network connections

options:
  -h, --help                  show this help message and exit
  --ipv4                      Show only IPv4 connections
  --ipv6                      Show only IPv6 connections
  --delay-closed SEC          Seconds to keep closed connections displayed (default: 10)
  --delay-new SEC             Seconds to highlight new connections (default: 10)
  --no-resolve                Disable DNS resolution (show raw IPs only)
  --split-port                Split IP and port into separate columns
  --poll-interval SEC         Seconds between connection polls (default: 1.0)
  --full-path                 Show full executable path for processes
  --traffic                   Enable traffic monitoring
  --security                  Enable security monitoring
  --security-config FILE      Path to security configuration file (JSON or YAML)
  --export-format {csv,json,yaml}  Export format for connection data
  --export-file FILE          Filename for exported connection data
  --export-alerts FILE        Filename for exported security alerts
  --filter-process FILTER     Filter connections by process name (case-insensitive)
  --filter-port PORT          Filter connections by remote port
  --filter-ip IP              Filter connections by remote IP address
```

## Project Structure

```
wtfcalls/
├── wtfcalls.py                   # Main executable file
├── connection.py                 # Connection class definitions
├── collector.py                  # Connection collection methods
├── dns_resolver.py               # DNS resolution handling
├── table.py                      # Table display handling
├── logger.py                     # Logging functions
├── traffic.py                    # Traffic monitoring
├── security.py                   # Security monitoring
├── wtfcalls_tui.py               # TUI interface
└── config/
    └── default_security.yaml     # Default security rules
```

## Security Features

The security module can detect potentially suspicious connections based on various heuristics. Create a YAML or JSON configuration file:

```yaml
# security_config.yaml
malicious_ips:
  - 198.51.100.123
  - 203.0.113.45

suspicious_ports:
  - 4444
  - 9050
  - 8888

trusted_processes:
  - firefox
  - chrome
  - apt

trusted_connections:
  - process: python3
    ip: 192.168.1.10

custom_rules:
  - name: "High port access"
    description: "Connection to high port number"
    condition: "conn.rp > 50000"
    threat_level: 1
    exceptions: ["torrent", "bittorrent"]
```

Run with the security configuration:

```bash
./wtfcalls.py --security --security-config security_config.yaml
```

## License

This project is licensed under the GPLv3 License.

## Acknowledgements

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process and system monitoring
- [Rich](https://github.com/Textualize/rich) - Terminal formatting 
- [Textual](https://github.com/Textualize/textual) - TUI framework
