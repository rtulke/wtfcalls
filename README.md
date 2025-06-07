# WTF Calls

<b>W</b>hat <b>T</b>he <b>F</b>uck Calls is a tool for live security and monitoring of network connections and processes.

![Example](/demo/wtfcalls.png)


## Features

- **Live Connection Monitoring**: Detect, filter and display all network connections in real-time
- **TUI Interface**: Advanced textual user interface with filtering and multiple views
- **Security Analysis**: Detect potentially suspicious connections based on configurable rules
- **Traffic Monitoring**: Track data transferred for each connection
- **Export Capabilities**: Export connection data and security alerts in CSV, JSON, or YAML format
- **Compatibility**: Works on Linux and macOS systems

## Installation


### Basic Installation (OS wide, Not recommended)

Required Python packages:
```bash
su - root
pip install --upgrade pip
pip install psutil rich textual pyyaml ipaddress
git clone https://github.com/rtulke/wtfcalls.git
cd wtfcalls
chmod +x wtfcalls.py
```
### Basic Installation (Debian based OS)

Required Python packages:
```bash
su - root
apt install python3-psutil python3-rich python3-textual python3-yaml -y
git clone https://github.com/rtulke/wtfcalls.git
cd wtfcalls
chmod +x wtfcalls.py
```

### Basic Installation (virtuall environment)

```bash
git clone https://github.com/rtulke/wtfcalls.git
cd wtfcalls
chmod +x wtfcalls.py
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```


## Usage

### Basic Usage

Run the basic monitoring interface:

```bash
./wtfcalls.py
```

### Command Line Options

```
usage: wtfcalls.py [-h] [-4] [-6] [-d SEC] [-n SEC] [-i] [-p SEC] [-c CONFIG] [-e {csv,json,yaml}] [-o EXPORT_FILE] [-a EXPORT_ALERTS] [-q] [-fp FILTER_PROCESS] [-fn FILTER_NAME]
                   [-ft FILTER_PORT] [-fi FILTER_IP] [-fa FILTER_ALERT [FILTER_ALERT ...]] [-fc {in,out}] [--debug]

wtfcalls: Interactive Network Connection Monitor

options:
  -h, --help                              Show this help message and exit
  -4, --ipv4                              Show only IPv4 connections (default: False)
  -6, --ipv6                              Show only IPv6 connections (default: False)
  -d, --delay-closed SEC                  Seconds to keep closed connections displayed (default: 10)
  -n, --delay-new SEC                     Seconds to highlight new connections (default: 10)
  -i, --show-ip                           Disable DNS resolution (show raw IPs only) (default: False)
  -p, --poll-interval SEC                 Seconds between connection polls (default: 1.0)
  -c, --config CONFIG                     Path to configuration file (JSON or YAML) (default: None)
  -e, --export-format {csv,json,yaml}     Export format for connection data (default: None)
  -o, --export-file EXPORT_FILE           Filename for exported connection data (default: None)
  -a, --export-alerts EXPORT_ALERTS       Filename for exported security alerts (default: None)
  -q, --quiet                             Suppress console warnings and only show the table (default: False)
  -fp, --filter-process FILTER_PROCESS    Filter connections by process IDs (comma-separated, supports ranges, e.g. "1-500,3330") (default: None)
  -fn, --filter-name FILTER_NAME          Filter connections by program names (comma-separated) (default: None)
  -ft, --filter-port FILTER_PORT          Filter connections by remote ports (comma-separated, supports ranges, e.g. "80,443,8000-8999") (default: None)
  -fi, --filter-ip FILTER_IP              Filter connections by remote IP addresses (comma-separated, supports CIDR notation, e.g. "192.168.1.0/24,10.0.0.1") (default: None)
  -fa, --filter-alert FILTER_ALERT [FILTER_ALERT ...]
                                          Filter connections by alert type (e.g., suspicious malicious trusted) (default: None)
  -fc, --filter-connection {in,out}       Filter connections by direction (in=inbound, out=outbound) (default: None)
  --debug                                 Show debug window for troubleshooting (default: False)
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
