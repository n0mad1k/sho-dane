# Shodan Search Tool

This tool allows you to perform lookups using the [Shodan API](https://www.shodan.io/) for a list of IP addresses or domain names. It provides comprehensive external attack surface mapping capabilities with features designed to maximize efficiency and minimize API credit usage.

## Features

- **IP Range Support**: Process CIDR notation (`192.168.1.0/24`) and dash notation (`192.168.1.1-192.168.1.254`)
- **Certificate Transparency Mining**: Discover subdomains through CT logs without consuming Shodan credits
- **ASN Lookup**: Automatically identify IP ranges owned by target organizations
- **Reverse DNS Enumeration**: Find additional domains associated with discovered IPs
- **Credit Optimization**: Smart features to minimize Shodan API credit usage
- **Verification Commands**: Generate a script with commands to validate findings
- **Tool-Friendly Output**: Create clean target lists for use with other security tools
- **Enhanced Reporting**: Comprehensive CSV, JSON, and summary reports
- **Batch Processing**: Process targets in batches to avoid rate limiting

## Requirements

- Python 3.x
- The following Python packages:
  - `shodan`
  - `argparse`
  - `argcomplete`
  - `configparser`
  - `requests`

You can install the required packages via pip:
```bash
pip install -r requirements.txt
```

## Configuration

To use the Shodan API, you need to create a `config.ini` file in the root of the project with the following structure:

```ini
[shodan]
api_key=YOUR_SHODAN_API_KEY
```

If you're using the `--help-me-im-poor` option, the `config.ini` file is not required as it will only open Shodan queries in Firefox without using the API.

## Usage

### Basic Command Structure
```bash
python sho_dane.py -t <targets_file> -o <output_directory> [options]
```

### Command Line Options

```
Basic Options:
  -t, --targets FILE       Path to file containing IPs/domains/organizations
  -s, --single-target      Specify a single target
  -H, --host               Perform Shodan host lookups for IP addresses
  -D, --dns                Perform DNS lookups for domains
  -E, --enhanced           Enable enhanced CT log discovery
  -o, --output DIR         Output directory (default: shodan_results)

Additional Features:
  -A, --asn-lookup         Enable ASN lookup for organizations 
  -R, --reverse-dns        Perform reverse DNS lookups on discovered IPs
  -V, --verification       Generate verification commands for discovered assets
  -T, --tools              Generate tool-friendly output files
  -b, --help-me-im-poor    Open Firefox tabs with Shodan queries (uses no API credits)

Credit Optimization:
  --full-data              Get full data from Shodan API (uses more credits)
  --batch-size INT         Targets to process in each batch (default: 10)
  --batch-delay INT        Delay between batches in seconds (default: 2)

Debugging:
  --debug                  Enable debug messages
```

### Example Usage

#### Basic External Attack Surface Mapping
```bash
python sho_dane.py -t targets.txt -H -D -E -o results
```

#### Generate Tool-Friendly Output Files
```bash
python sho_dane.py -t targets.txt -H -D -E -A -R -T -o tool_output
```

#### Generate Verification Commands
```bash
python sho_dane.py -t targets.txt -H -D -V -o verification_results
```

#### Credit-Optimized Scanning
```bash
python sho_dane.py -t targets.txt -H -D -E -A -R --batch-size 5 --batch-delay 3 -o efficient_scan
```

#### API-Free Mode (Firefox Tabs)
```bash
python sho_dane.py -t targets.txt --help-me-im-poor
```

## Output Files

The tool generates several output files:

### Standard Reports
- **Quick Results TXT**: Human-readable summary of findings
- **Full Results JSON**: Complete data for all discovered assets
- **CSV Report**: Spreadsheet-friendly format for analysis
- **Summary Report**: High-level overview with key statistics

### Tool-Friendly Output (`-T` flag)
- **IP Targets File**: List of discovered IP addresses
- **Domain Targets File**: List of discovered domains
- **All Targets File**: Combined list of IPs and domains
- **Nmap Commands**: Ready-to-use nmap command examples

### Verification Script (`-V` flag)
- **Verification Commands**: Bash script with commands to verify and validate findings

## Workflow Recommendations

1. Start with a focused scan to identify the key assets:
   ```bash
   python sho_dane.py -s example.com -H -D -E -o initial_scan
   ```

2. Generate tool-friendly output files for further analysis:
   ```bash
   python sho_dane.py -t targets.txt -H -D -E -T -o tool_output
   ```

3. Use the generated files with other security tools:
   ```bash
   # IP scan with nmap
   nmap -sS -sV -p- -oA nmap_scan -iL tool_output/20250401-123456_ip_targets.txt

   # Domain web scanning with httpx
   cat tool_output/20250401-123456_domain_targets.txt | httpx -title -tech-detect

   # Vulnerability scanning with nuclei
   nuclei -l tool_output/20250401-123456_all_targets.txt -t cves/
   ```

4. Generate and run verification commands to validate findings:
   ```bash
   python sho_dane.py -t confirmed_targets.txt -H -D -V -o verification
   chmod +x verification/20250401-123456_verification_commands.sh
   ./verification/20250401-123456_verification_commands.sh
   ```

## Advanced Features

### Certificate Transparency Log Mining
The `-E` flag enables discovery of subdomains through Certificate Transparency logs, which doesn't consume Shodan credits:

```bash
python sho_dane.py -s example.com -D -E -o ct_results
```

### ASN-based Discovery
To discover and scan all IP ranges owned by organizations listed in your targets file:

```bash
python sho_dane.py -t organizations.txt -A -H -o asn_results
```

Where organizations.txt contains organization names, one per line.

### Mixed Target Types
The tool supports mixed target types in a single file:

```bash
python sho_dane.py -t mixed_targets.txt -H -D -E -A -R -o mixed_results
```

Where mixed_targets.txt might contain:
```
example.com
192.168.1.1
10.0.0.0/24
172.16.1.1-172.16.1.100
Acme Corporation
```

## License

This tool is for educational and ethical use only. Use responsibly and only on systems you own or have explicit permission to test.