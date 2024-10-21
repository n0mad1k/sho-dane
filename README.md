# Shodan Search Tool

This tool allows you to perform lookups using the [Shodan API](https://www.shodan.io/) for a list of IP addresses or domain names. You can use it to gather DNS and host information, open Shodan queries in your browser, and save results locally in both human-readable and JSON formats.

## Features
- Perform Shodan DNS lookups for domains.
- Perform Shodan host lookups for IP addresses.
- Open Shodan queries in Firefox tabs without using the Shodan API (`--help-me-im-poor`).
- Save results to a local directory in both formatted text and JSON formats.
- Support for both bulk lookups (from a file) and single-target lookups.
- Debug mode for troubleshooting.

## Requirements
- Python 3.x
- The following Python packages:
  - `shodan`
  - `argparse`
  - `argcomplete`
  - `configparser`

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

### General Command Structure
```bash
python shodan_search.py -t <targets_file> -o <output_directory> [options]
```

### Options
- `-t, --targets`: Path to the file containing the list of IPs or domains (one per line).
- `-s, --single-target`: Specify a single domain or IP address for lookup.
- `-H, --host`: Perform Shodan host lookups for IP addresses.
- `-D, --dns`: Perform DNS lookups for domains.
- `--help-me-im-poor`: Open Firefox tabs with Shodan queries for each target without using the API.
- `-o, --output`: Output directory to save the results (default: `shodan_results`).
- `--debug`: Enable debug messages for troubleshooting.

### Example Usage

#### Host Lookups for IPs
To perform Shodan host lookups for a list of IPs:
```bash
python shodan_search.py -t targets.txt -H -o results
```

#### DNS Lookups for Domains
To perform Shodan DNS lookups for a list of domains:
```bash
python shodan_search.py -t domains.txt -D -o dns_results
```

#### Single Target Lookup
To perform a Shodan lookup for a single IP or domain:
```bash
python shodan_search.py -s example.com -H -o single_target_result
```

#### Open Shodan Queries in Firefox
To open Shodan queries for IPs or domains in Firefox tabs without using the API:
```bash
python shodan_search.py -t targets.txt --help-me-im-poor
```

### Debug Mode
Enable debug mode to get additional information during execution:
```bash
python shodan_search.py -t targets.txt -H --debug
```

## Output
The results are saved in two formats:
- **Formatted Text File**: A human-readable file summarizing the results.
- **JSON File**: A complete JSON file with detailed lookup information.

Both files will be saved in the output directory specified using the `-o` option.

## Example Configuration File (`config.ini`)
```ini
[shodan]
api_key=YOUR_SHODAN_API_KEY
```


