import shodan
import configparser
import argparse
import argcomplete
import socket
import json
import os
import subprocess
import time
import ipaddress
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    print("Error: Missing 'requests' module. Please install it using: pip install requests")
    import sys
    sys.exit(1)


# Read API key from config.ini file
def get_shodan_api_key(config_file='config.ini', debug=False):
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        raise FileNotFoundError(
            f"Error: '{config_file}' is required for this operation but was not found.\n"
            "Please create a 'config.ini' file with the following structure:\n\n"
            "[shodan]\napi_key=YOUR_SHODAN_API_KEY\n"
        )
    config.read(config_file)
    if debug:
        print(f"[DEBUG] Reading API key from: {config_file}")
    return config['shodan']['api_key']


# Extract base domain by stripping subdomains (for DNS lookups)
def extract_base_domain(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])  # Extract base domain (second-level and top-level domain)
    return domain


# Deduplicate domains (for DNS lookups) by removing subdomains
def deduplicate_domains(domains, debug=False):
    deduped_domains = set(extract_base_domain(domain) for domain in domains)
    if debug:
        print(f"[DEBUG] Deduplicated domains for DNS: {deduped_domains}")
    return list(deduped_domains)


# Function to check if a target is an IP address
def is_ip(target, debug=False):
    try:
        socket.inet_aton(target)
        if debug:
            print(f"[DEBUG] {target} is a valid IP address.")
        return True
    except socket.error:
        if debug:
            print(f"[DEBUG] {target} is not a valid IP address.")
        return False


# Function to check if a target is a CIDR range
def is_cidr(target, debug=False):
    try:
        ipaddress.ip_network(target, strict=False)
        if debug:
            print(f"[DEBUG] {target} is a valid CIDR notation.")
        return True
    except ValueError:
        if debug:
            print(f"[DEBUG] {target} is not a valid CIDR notation.")
        return False


# Function to check if a target is a dash-notation range
def is_ip_range(target, debug=False):
    if '-' not in target:
        return False
    
    start_ip, end_ip = target.split('-', 1)
    
    # Check if both parts are valid IPs
    try:
        socket.inet_aton(start_ip)
        if '.' not in end_ip:  # Handle cases like "192.168.1.1-254"
            # Extract the last octet from start_ip
            prefix = start_ip.rsplit('.', 1)[0]
            end_ip = f"{prefix}.{end_ip}"
        socket.inet_aton(end_ip)
        if debug:
            print(f"[DEBUG] {target} is a valid IP range.")
        return True
    except socket.error:
        if debug:
            print(f"[DEBUG] {target} is not a valid IP range.")
        return False


# Function to expand CIDR notation to individual IPs
def expand_cidr(cidr, debug=False):
    network = ipaddress.ip_network(cidr, strict=False)
    ips = [str(ip) for ip in network]
    if debug:
        print(f"[DEBUG] Expanded CIDR {cidr} to {len(ips)} IPs")
    return ips


# Function to expand dash notation to individual IPs
def expand_ip_range(ip_range, debug=False):
    start_ip, end_ip = ip_range.split('-', 1)
    
    # Handle abbreviated range (e.g., 192.168.1.1-254)
    if '.' not in end_ip:
        prefix = start_ip.rsplit('.', 1)[0]
        end_ip = f"{prefix}.{end_ip}"
    
    # Convert IPs to integers for easier range generation
    start_ipint = int(ipaddress.IPv4Address(start_ip))
    end_ipint = int(ipaddress.IPv4Address(end_ip))
    
    if start_ipint > end_ipint:
        raise ValueError(f"Invalid IP range: {ip_range}. Start IP must be less than end IP.")
    
    # Generate list of IPs in the range
    ips = [str(ipaddress.IPv4Address(i)) for i in range(start_ipint, end_ipint + 1)]
    
    if debug:
        print(f"[DEBUG] Expanded IP range {ip_range} to {len(ips)} IPs")
    
    return ips


# Process and expand IP ranges in target list
def process_ip_ranges(targets, debug=False):
    expanded_targets = []
    
    for target in targets:
        if is_cidr(target, debug):
            expanded_targets.extend(expand_cidr(target, debug))
        elif is_ip_range(target, debug):
            expanded_targets.extend(expand_ip_range(target, debug))
        else:
            expanded_targets.append(target)
    
    if debug:
        print(f"[DEBUG] Expanded {len(targets)} targets to {len(expanded_targets)} individual targets")
    
    return expanded_targets


# Query certificate transparency logs for a domain
def query_certificate_logs(domain, debug=False):
    """Query certificate transparency logs for a given domain to discover subdomains"""
    base_domain = extract_base_domain(domain)
    crt_sh_url = f"https://crt.sh/?q=%.{base_domain}&output=json"
    
    try:
        response = requests.get(crt_sh_url, timeout=30)
        if response.status_code == 200:
            certificates = response.json()
            # Extract unique domain names from certificates
            domains = set()
            for cert in certificates:
                # Extract name value
                name = cert.get('name_value')
                if name:
                    # Split multi-domain certificates
                    for domain_name in name.split('\n'):
                        domains.add(domain_name.lower())
            
            if debug:
                print(f"[DEBUG] Found {len(domains)} unique domains from CT logs for {base_domain}")
            
            return list(domains)
        else:
            if debug:
                print(f"[DEBUG] CT log query returned status code {response.status_code}")
    except Exception as e:
        if debug:
            print(f"[DEBUG] Error querying CT logs: {e}")
    
    return []


# Get ASN information for an organization
def get_asn_info(organization, debug=False):
    """Get ASN information and related CIDR blocks for an organization"""
    try:
        search_url = f"https://api.bgpview.io/search?query_term={organization}"
        response = requests.get(search_url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            asns = []
            
            # Extract ASNs
            if 'asns' in data.get('data', {}):
                for asn in data['data']['asns']:
                    asns.append({
                        'asn': asn['asn'],
                        'name': asn['name'],
                        'description': asn['description']
                    })
                    
                    # For each ASN, get related CIDR blocks
                    asn_url = f"https://api.bgpview.io/asn/{asn['asn']}/prefixes"
                    asn_response = requests.get(asn_url, timeout=30)
                    
                    if asn_response.status_code == 200:
                        asn_data = asn_response.json()
                        prefixes = []
                        
                        if 'ipv4_prefixes' in asn_data.get('data', {}):
                            for prefix in asn_data['data']['ipv4_prefixes']:
                                prefixes.append({
                                    'prefix': prefix['prefix'],
                                    'description': prefix.get('description', 'N/A')
                                })
                        
                        asns[-1]['prefixes'] = prefixes
            
            if debug:
                print(f"[DEBUG] Found {len(asns)} ASNs for {organization}")
            
            return asns
    except Exception as e:
        if debug:
            print(f"[DEBUG] Error getting ASN info: {e}")
    
    return []


# Resolve and deduplicate IP addresses for host lookups (keep subdomains)
def resolve_and_deduplicate_ips(domains, debug=False):
    resolved_ips = {}
    for domain in domains:
        try:
            if is_ip(domain, debug):
                resolved_ips[domain] = domain
            else:
                ip_address = socket.gethostbyname(domain)
                resolved_ips[domain] = ip_address
            if debug:
                print(f"[DEBUG] Resolved {domain} to {resolved_ips[domain]}")
        except socket.gaierror:
            if debug:
                print(f"[DEBUG] Could not resolve domain: {domain}")
            resolved_ips[domain] = None
    # Deduplicate IP addresses
    unique_ips = set(resolved_ips.values()) - {None}
    if debug:
        print(f"[DEBUG] Deduplicated IPs for Host Lookup: {unique_ips}")
    return list(unique_ips)


# Perform reverse DNS lookups for a list of IPs
def reverse_dns_lookup(ips, debug=False):
    """Perform reverse DNS lookups for a list of IP addresses"""
    results = {}
    
    def lookup_single_ip(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return ip, hostname
        except (socket.herror, socket.gaierror):
            return ip, None
    
    # Use ThreadPoolExecutor for parallel lookups
    with ThreadPoolExecutor(max_workers=10) as executor:
        lookup_results = list(executor.map(lookup_single_ip, ips))
    
    for ip, hostname in lookup_results:
        results[ip] = hostname
        if debug and hostname:
            print(f"[DEBUG] Reverse DNS: {ip} → {hostname}")
    
    return results


# Execute the host lookups with credit optimization
def shodan_host_lookups(ips, api, debug=False, min_credits=True):
    results = {}
    success_count = 0
    error_count = 0
    
    unique_ips = list(set(ips))
    if debug:
        print(f"[DEBUG] Unique IPs for lookup: {unique_ips}")
    
    # If min_credits is enabled, use the minify option to save credits
    minify_option = True if min_credits else False
    
    if min_credits and debug:
        print(f"[DEBUG] Using minified results to save credits. Only basic data will be returned.")
    
    for ip in unique_ips:
        try:
            if debug:
                print(f"[DEBUG] Looking up IP: {ip}")
            host_info = api.host(ip, minify=minify_option)
            success_count += 1
            
            # Extract the available data based on minify option
            if minify_option:
                results[ip] = {
                    "IP": host_info.get("ip_str", "N/A"),
                    "Organization": host_info.get("org", "N/A"),
                    "ISP": host_info.get("isp", "N/A"),
                    "ASN": host_info.get("asn", "N/A"),
                    "Hostnames": host_info.get("hostnames", []),
                    "Open Ports": host_info.get("ports", []),
                    "Last Update": host_info.get("last_update", "N/A"),
                    "Location": {
                        "City": host_info.get("city", "N/A"),
                        "Country": host_info.get("country_name", "N/A")
                    },
                    "Credit Usage": "Minimal (1 credit)",
                    "Source": "Shodan Host API (Minified)"
                }
            else:
                results[ip] = {
                    "IP": host_info.get("ip_str", "N/A"),
                    "Organization": host_info.get("org", "N/A"),
                    "ISP": host_info.get("isp", "N/A"),
                    "ASN": host_info.get("asn", "N/A"),
                    "Operating System": host_info.get("os", "N/A"),
                    "Open Ports": host_info.get("ports", []),
                    "Hostnames": host_info.get("hostnames", []),
                    "Tags": host_info.get("tags", []),
                    "Last Update": host_info.get("last_update", "N/A"),
                    "Location": {
                        "City": host_info.get("city", "N/A"),
                        "Country": host_info.get("country_name", "N/A")
                    },
                    "Data": host_info.get("data", []),
                    "Credit Usage": "Full (1 credit)",
                    "Source": "Shodan Host API (Full)"
                }
        except shodan.APIError as e:
            error_count += 1
            if debug:
                print(f"[DEBUG] Error looking up {ip}: {e}")
            results[ip] = {"Error": str(e)}
    return results, success_count, error_count


# Function to perform DNS lookups for domains with enhanced discovery and credit optimization
def shodan_dns_lookups(domains, api, debug=False, enhanced=False, min_credits=True):
    results = {}
    success_count = 0
    error_count = 0
    
    # If enhanced discovery is enabled but credit optimization is prioritized
    # Limit the enhanced discovery to just CT logs which doesn't use Shodan credits
    all_domains = set(domains)
    if enhanced:
        for domain in domains:
            ct_domains = query_certificate_logs(domain, debug)
            if ct_domains:
                all_domains.update(ct_domains)
                if debug:
                    print(f"[DEBUG] Enhanced discovery added {len(ct_domains)} domains from CT logs")
    
    all_domains = list(all_domains)
    if debug:
        print(f"[DEBUG] Processing {len(all_domains)} domains for DNS lookups")

    # Calculate potential credit usage
    estimated_credits = len(all_domains)
    if estimated_credits > 10 and min_credits:
        print(f"[WARNING] Performing DNS lookups on {len(all_domains)} domains would use approximately {estimated_credits} credits.")
        print("[INFO] To save credits, only looking up base domains...")
        
        # Deduplicate to base domains only when trying to minimize credits
        base_domains = deduplicate_domains(all_domains, debug=debug)
        all_domains = base_domains
        estimated_credits = len(all_domains)
        print(f"[INFO] Reduced to {len(all_domains)} base domains ({estimated_credits} credits)")

    for domain in all_domains:
        try:
            if debug:
                print(f"[DEBUG] Looking up DNS information for: {domain}")
            dns_info = api.dns.domain_info(domain)
            success_count += 1
            results[domain] = {
                'Domain': domain,
                'Subdomains': dns_info.get('subdomains', []),
                'Tags': dns_info.get('tags', []),
                'DNS Records': dns_info.get('dns', {}),
                'Source': 'Shodan DNS API',
                'Credit Usage': '1 credit'
            }
            
            # Only when credit optimization is off, add discovered subdomains to results
            if not min_credits and 'subdomains' in dns_info and dns_info['subdomains']:
                for subdomain in dns_info['subdomains']:
                    full_subdomain = f"{subdomain}.{domain}"
                    if full_subdomain not in results:
                        results[full_subdomain] = {
                            'Domain': full_subdomain,
                            'Source': 'Shodan Subdomain Discovery',
                            'Credit Usage': '0 credits (derived)'
                        }
        except shodan.APIError as e:
            error_count += 1
            if debug:
                print(f"[DEBUG] Error looking up DNS for {domain}: {e}")
            results[domain] = {"Domain": domain, "Error": str(e), "Source": "Shodan DNS API"}

    return results, success_count, error_count


# Read target list from a file
def process_target_list(file_path, debug=False):
    if debug:
        print(f"[DEBUG] Looking for the target file at: {file_path}")
    try:
        with open(file_path, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
            if debug:
                print(f"[DEBUG] Targets read from file: {targets}")
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return []
    return targets


# Helper function to map common ports to service names
def get_common_service_name(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP (Submission)",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5901: "VNC-1",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    return common_ports.get(port, "Unknown Service")


# Generate verification commands for discovered assets
def generate_verification_commands(results, output_file, debug=False):
    """Generate a list of commands to verify the discovered assets"""
    
    verification_commands = []
    
    # Add header and timestamp
    verification_commands.append("#!/bin/bash")
    verification_commands.append(f"# Verification commands generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    verification_commands.append("# Run this script to verify the attack surface")
    verification_commands.append("")
    
    # Get unique IPs and domains
    ip_targets = []
    domain_targets = []
    organized_targets = {}  # Group targets by organization
    
    for target, data in results.items():
        # Extract organization info if available
        org = data.get('Organization', 'Unknown')
        if org not in organized_targets:
            organized_targets[org] = {'ips': [], 'domains': []}
        
        if is_ip(target, debug=False):
            ip_targets.append(target)
            organized_targets[org]['ips'].append(target)
        elif '.' in target and not target.startswith(' '):
            domain_targets.append(target)
            organized_targets[org]['domains'].append(target)
            
        # Also extract IPs from DNS records
        if 'DNS Records' in data and isinstance(data['DNS Records'], dict):
            for record_type, records in data['DNS Records'].items():
                if record_type in ['A', 'AAAA'] and isinstance(records, list):
                    for record in records:
                        if 'value' in record and is_ip(record['value'], debug=False):
                            ip_targets.append(record['value'])
                            organized_targets[org]['ips'].append(record['value'])
    
    # Remove duplicates
    ip_targets = list(set(ip_targets))
    domain_targets = list(set(domain_targets))
    for org in organized_targets:
        organized_targets[org]['ips'] = list(set(organized_targets[org]['ips']))
        organized_targets[org]['domains'] = list(set(organized_targets[org]['domains']))
    
    # Add command to create target files
    verification_commands.append("# Create target files for use with other tools")
    verification_commands.append("mkdir -p verification_data")
    
    # Create all IPs file
    if ip_targets:
        verification_commands.append("\n# All discovered IPs")
        verification_commands.append("cat << 'EOF' > verification_data/all_ips.txt")
        for ip in sorted(ip_targets):
            verification_commands.append(ip)
        verification_commands.append("EOF")
        verification_commands.append("echo \"Created verification_data/all_ips.txt with $(wc -l < verification_data/all_ips.txt) IPs\"")
    
    # Create all domains file
    if domain_targets:
        verification_commands.append("\n# All discovered domains")
        verification_commands.append("cat << 'EOF' > verification_data/all_domains.txt")
        for domain in sorted(domain_targets):
            verification_commands.append(domain)
        verification_commands.append("EOF")
        verification_commands.append("echo \"Created verification_data/all_domains.txt with $(wc -l < verification_data/all_domains.txt) domains\"")
    
    # Create organization-specific files
    for org in organized_targets:
        if org != 'Unknown' and org != 'N/A':
            org_safe_name = org.replace(' ', '_').replace(',', '').replace('/', '_').lower()
            
            if organized_targets[org]['ips']:
                verification_commands.append(f"\n# IPs associated with '{org}'")
                verification_commands.append(f"cat << 'EOF' > verification_data/{org_safe_name}_ips.txt")
                for ip in sorted(organized_targets[org]['ips']):
                    verification_commands.append(ip)
                verification_commands.append("EOF")
                verification_commands.append(f"echo \"Created verification_data/{org_safe_name}_ips.txt with $(wc -l < verification_data/{org_safe_name}_ips.txt) IPs\"")
            
            if organized_targets[org]['domains']:
                verification_commands.append(f"\n# Domains associated with '{org}'")
                verification_commands.append(f"cat << 'EOF' > verification_data/{org_safe_name}_domains.txt")
                for domain in sorted(organized_targets[org]['domains']):
                    verification_commands.append(domain)
                verification_commands.append("EOF")
                verification_commands.append(f"echo \"Created verification_data/{org_safe_name}_domains.txt with $(wc -l < verification_data/{org_safe_name}_domains.txt) domains\"")
    
    # Add automated verification commands
    verification_commands.append("\n# =======================================")
    verification_commands.append("# AUTOMATED VERIFICATION COMMANDS")
    verification_commands.append("# =======================================")
    
    # Add function to check if a tool exists
    verification_commands.append("""
# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}
""")
    
    # Add IP verification commands
    if ip_targets:
        verification_commands.append("\n# === IP VERIFICATION ===")
        
        # Basic connectivity checks
        verification_commands.append("\necho \"\\n[+] Performing basic connectivity checks...\"\n")
        verification_commands.append("for ip in $(cat verification_data/all_ips.txt); do")
        verification_commands.append("  echo -n \"$ip - Ping: \"")
        verification_commands.append("  ping -c 1 -W 1 $ip > /dev/null 2>&1")
        verification_commands.append("  if [ $? -eq 0 ]; then echo \"Reachable\"; else echo \"Unreachable\"; fi")
        verification_commands.append("done")
        
        # Port scanning with nmap if available
        verification_commands.append("\necho \"\\n[+] Performing port scanning...\"\n")
        verification_commands.append("if command_exists nmap; then")
        verification_commands.append("  for ip in $(cat verification_data/all_ips.txt | head -n 10); do")  # Limit to first 10 for performance
        verification_commands.append("    echo \"\\nScanning $ip for common ports...\"")
        verification_commands.append("    nmap -F --open $ip")
        verification_commands.append("  done")
        verification_commands.append("else")
        verification_commands.append("  echo \"nmap not found. Install with: apt-get install nmap\"")
        verification_commands.append("fi")
        
        # Web service detection
        verification_commands.append("\necho \"\\n[+] Checking for web services...\"\n")
        verification_commands.append("for ip in $(cat verification_data/all_ips.txt); do")
        verification_commands.append("  echo -n \"$ip - HTTP: \"")
        verification_commands.append("  curl -s -I -m 3 http://$ip/ | head -n 1 || echo \"No response\"")
        verification_commands.append("  echo -n \"$ip - HTTPS: \"")
        verification_commands.append("  curl -s -I -m 3 -k https://$ip/ | head -n 1 || echo \"No response\"")
        verification_commands.append("done")
    
    # Add domain verification commands
    if domain_targets:
        verification_commands.append("\n# === DOMAIN VERIFICATION ===")
        
        # DNS resolution
        verification_commands.append("\necho \"\\n[+] Resolving domains to IP addresses...\"\n")
        verification_commands.append("for domain in $(cat verification_data/all_domains.txt); do")
        verification_commands.append("  echo -n \"$domain resolves to: \"")
        verification_commands.append("  dig +short A $domain || echo \"Failed to resolve\"")
        verification_commands.append("done")
        
        # Web service verification
        verification_commands.append("\necho \"\\n[+] Checking domain web services...\"\n")
        verification_commands.append("for domain in $(cat verification_data/all_domains.txt); do")
        verification_commands.append("  echo \"Testing $domain:\"")
        verification_commands.append("  echo -n \"  HTTP: \"")
        verification_commands.append("  curl -s -I -m 3 http://$domain/ | head -n 1 || echo \"No response\"")
        verification_commands.append("  echo -n \"  HTTPS: \"")
        verification_commands.append("  curl -s -I -m 3 -k https://$domain/ | head -n 1 || echo \"No response\"")
        verification_commands.append("done")
        
        # SSL certificate verification
        verification_commands.append("\necho \"\\n[+] Checking SSL certificates...\"\n")
        verification_commands.append("if command_exists openssl; then")
        verification_commands.append("  for domain in $(cat verification_data/all_domains.txt | head -n 5); do")  # Limit to first 5 for performance
        verification_commands.append("    echo \"\\nCertificate for $domain:\"")
        verification_commands.append("    echo | openssl s_client -connect $domain:443 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|Issuer:|Not Before:|Not After:' || echo \"Failed to retrieve certificate\"")
        verification_commands.append("  done")
        verification_commands.append("else")
        verification_commands.append("  echo \"openssl not found. Install with: apt-get install openssl\"")
        verification_commands.append("fi")
    
    # Add recommendations for advanced verification
    verification_commands.append("\n# === RECOMMENDED ADVANCED VERIFICATION TOOLS ===")
    verification_commands.append("\necho \"\\n[+] Recommendations for further verification:\"")
    verification_commands.append("echo \"  - Use Nmap for detailed port scanning: nmap -sV -p- -iL verification_data/all_ips.txt\"")
    verification_commands.append("echo \"  - Use Nuclei for vulnerability scanning: nuclei -l verification_data/all_domains.txt -t cves/\"")
    verification_commands.append("echo \"  - Use Amass for subdomain enumeration: amass enum -d domain.com\"")
    verification_commands.append("echo \"  - Use Shodan CLI for detailed info: shodan host ip-address\"")
    verification_commands.append("echo \"  - Use HTTPx for web technology detection: cat verification_data/all_domains.txt | httpx -title -tech-detect\"")
    
    # Write the commands to the output file
    with open(output_file, 'w') as f:
        f.write('\n'.join(verification_commands))
    
    # Make the file executable
    try:
        os.chmod(output_file, 0o755)
    except:
        if debug:
            print(f"[DEBUG] Failed to make {output_file} executable. You may need to run: chmod +x {output_file}")
    
    if debug:
        print(f"[DEBUG] Generated {len(verification_commands)} verification commands")
    
    return verification_commands


# Generate tool-friendly output files
def generate_tool_output(results, output_dir, debug=False):
    """Generate clean output files containing just IPs and domains for use with other tools"""
    
    # Get unique IPs and domains
    ip_targets = []
    domain_targets = []
    
    for target, data in results.items():
        if is_ip(target, debug=False):
            ip_targets.append(target)
        elif '.' in target and not target.startswith(' '):
            domain_targets.append(target)
            
        # Also extract IPs from DNS records
        if 'DNS Records' in data and isinstance(data['DNS Records'], dict):
            for record_type, records in data['DNS Records'].items():
                if record_type in ['A', 'AAAA'] and isinstance(records, list):
                    for record in records:
                        if 'value' in record and is_ip(record['value'], debug=False):
                            ip_targets.append(record['value'])
    
    # Remove duplicates and sort
    ip_targets = sorted(list(set(ip_targets)))
    domain_targets = sorted(list(set(domain_targets)))
    
    # Create the output files directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    # Create IP targets file
    if ip_targets:
        ip_file = os.path.join(output_dir, f"{timestamp}_ip_targets.txt")
        with open(ip_file, 'w') as f:
            f.write('\n'.join(ip_targets))
        print(f"[INFO] {len(ip_targets)} IP targets saved to: {ip_file}")
        
        if debug:
            print(f"[DEBUG] IP targets: {ip_targets}")
    
    # Create domain targets file
    if domain_targets:
        domain_file = os.path.join(output_dir, f"{timestamp}_domain_targets.txt")
        with open(domain_file, 'w') as f:
            f.write('\n'.join(domain_targets))
        print(f"[INFO] {len(domain_targets)} domain targets saved to: {domain_file}")
        
        if debug:
            print(f"[DEBUG] Domain targets: {domain_targets}")
    
    # Create combined targets file (for tools that can handle both)
    all_targets = ip_targets + domain_targets
    if all_targets:
        all_file = os.path.join(output_dir, f"{timestamp}_all_targets.txt")
        with open(all_file, 'w') as f:
            f.write('\n'.join(all_targets))
        print(f"[INFO] {len(all_targets)} total targets saved to: {all_file}")
        
        # Create a nmap command file
        nmap_file = os.path.join(output_dir, f"{timestamp}_nmap_commands.txt")
        with open(nmap_file, 'w') as f:
            # Add standard scan for IPs
            if ip_targets:
                f.write(f"# IP address scan - standard\n")
                f.write(f"nmap -sS -sV -oA {output_dir}/nmap_ip_scan -iL {ip_file}\n\n")
                
                f.write(f"# IP address scan - comprehensive\n")
                f.write(f"nmap -sS -sV -p- -oA {output_dir}/nmap_ip_scan_all_ports -iL {ip_file}\n\n")
            
            # Add web scan for domains
            if domain_targets:
                f.write(f"# Domain scan - web services\n")
                f.write(f"nmap -sS -sV -p 80,443,8080,8443 -oA {output_dir}/nmap_web_scan -iL {domain_file}\n\n")
            
            # Add all targets scan
            f.write(f"# All targets - quick scan\n")
            f.write(f"nmap -sS -F -oA {output_dir}/nmap_all_quick -iL {all_file}\n")
        
        print(f"[INFO] Nmap command examples saved to: {nmap_file}")
    
    return ip_targets, domain_targets, all_targets


# Save results to a local directory with specified output files for host and DNS queries
def save_results_to_directory(results, output_dir, success_count, error_count, is_host_query, is_dns_query, debug=False):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Determine filenames based on query type
    report_prefix = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    if is_host_query:
        formatted_file = os.path.join(output_dir, f'{report_prefix}_shodan_host_query_quick_results.txt')
        json_file = os.path.join(output_dir, f'{report_prefix}_shodan_host_query_full_results.json')
        csv_file = os.path.join(output_dir, f'{report_prefix}_shodan_host_query_results.csv')
        summary_file = os.path.join(output_dir, f'{report_prefix}_shodan_host_query_summary.txt')
        verification_file = os.path.join(output_dir, f'{report_prefix}_verification_commands.sh')
    elif is_dns_query:
        formatted_file = os.path.join(output_dir, f'{report_prefix}_shodan_domain_query_quick_results.txt')
        json_file = os.path.join(output_dir, f'{report_prefix}_shodan_domain_query_full_results.json')
        csv_file = os.path.join(output_dir, f'{report_prefix}_shodan_domain_query_results.csv')
        summary_file = os.path.join(output_dir, f'{report_prefix}_shodan_domain_query_summary.txt')
        verification_file = os.path.join(output_dir, f'{report_prefix}_verification_commands.sh')
    else:
        formatted_file = os.path.join(output_dir, f'{report_prefix}_shodan_query_quick_results.txt')
        json_file = os.path.join(output_dir, f'{report_prefix}_shodan_query_full_results.json')
        csv_file = os.path.join(output_dir, f'{report_prefix}_shodan_query_results.csv')
        summary_file = os.path.join(output_dir, f'{report_prefix}_shodan_query_summary.txt')
        verification_file = os.path.join(output_dir, f'{report_prefix}_verification_commands.sh')

    # Formatted text output
    formatted_output = "\n======= Lookup Results =======\n\n"
    
    # Prepare CSV data
    csv_headers = ["Target", "Type", "Source", "Organization", "ASN", "Open Ports", "Location", "Details"]
    csv_rows = []
    
    # Statistics for summary
    stats = {
        "total_targets": len(results),
        "successful_lookups": success_count,
        "failed_lookups": error_count,
        "domains_found": 0,
        "ips_found": 0,
        "open_ports": set(),
        "organizations": set(),
        "asns": set(),
        "countries": set()
    }
    
    for target, data in results.items():
        if 'Error' in data:
            formatted_output += f"Domain/IP: {target}\n  Error: {data['Error']}\n"
            csv_rows.append([target, "Unknown", data.get('Source', 'N/A'), "N/A", "N/A", "N/A", "N/A", f"Error: {data['Error']}"])
        elif is_host_query and 'Location' in data:
            # Host Lookup Results
            stats["ips_found"] += 1
            stats["open_ports"].update(data.get('Open Ports', []))
            if data.get('Organization') != 'N/A':
                stats["organizations"].add(data.get('Organization'))
            if data.get('ASN') != 'N/A':
                stats["asns"].add(data.get('ASN'))
            if data.get('Location', {}).get('Country') != 'N/A':
                stats["countries"].add(data.get('Location', {}).get('Country'))
                
            formatted_output += f"Domain/IP: {target}\n"
            formatted_output += f"  IP: {data['IP']}\n"
            formatted_output += f"  Organization: {data['Organization']}\n"
            formatted_output += f"  ISP: {data['ISP']}\n"
            formatted_output += f"  ASN: {data['ASN']}\n"
            formatted_output += f"  Location: {data['Location'].get('City', 'N/A')}, {data['Location'].get('Country', 'N/A')}\n"
            formatted_output += f"  Last Update: {data.get('Last Update', 'N/A')}\n"
            formatted_output += f"  Open Ports: {data.get('Open Ports', [])}\n"
            
            csv_rows.append([
                target, 
                "IP", 
                data.get('Source', 'Shodan Host API'),
                data.get('Organization', 'N/A'),
                data.get('ASN', 'N/A'),
                ", ".join(map(str, data.get('Open Ports', []))),
                f"{data.get('Location', {}).get('City', 'N/A')}, {data.get('Location', {}).get('Country', 'N/A')}",
                f"ISP: {data.get('ISP', 'N/A')}"
            ])
        elif is_dns_query:
            # DNS Lookup Results
            stats["domains_found"] += 1
            
            formatted_output += f"Domain/IP: {target}\n"
            formatted_output += f"  Source: {data.get('Source', 'N/A')}\n"
            formatted_output += f"  Subdomains: {data.get('Subdomains', 'N/A')}\n"
            formatted_output += f"  Tags: {data.get('Tags', 'N/A')}\n"
            formatted_output += f"  DNS Records: {data.get('DNS Records', 'N/A')}\n"
            
            csv_rows.append([
                target, 
                "Domain", 
                data.get('Source', 'N/A'),
                "N/A", 
                "N/A", 
                "N/A", 
                "N/A",
                f"Subdomains: {len(data.get('Subdomains', []))}, Tags: {', '.join(data.get('Tags', []))}"
            ])
        formatted_output += "-" * 60 + "\n"

    # Create metadata
    metadata = {
        "Total Targets": stats["total_targets"],
        "Successful Lookups": stats["successful_lookups"],
        "Failed Lookups": stats["failed_lookups"],
        "Domains Found": stats["domains_found"],
        "IPs Found": stats["ips_found"],
        "Unique Organizations": list(stats["organizations"]),
        "Unique ASNs": list(stats["asns"]),
        "Countries": list(stats["countries"]),
        "Open Ports": list(stats["open_ports"]),
        "Generated On": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Description": "Shodan Lookup Results with detailed host and DNS information.",
    }
    
    complete_results = {
        "Metadata": metadata,
        "Results": results
    }

    # Create summary report
    summary_output = "\n======= ATTACK SURFACE SUMMARY REPORT =======\n\n"
    summary_output += f"Generated On: {metadata['Generated On']}\n"
    summary_output += f"Total Targets Analyzed: {metadata['Total Targets']}\n"
    summary_output += f"Successful Lookups: {metadata['Successful Lookups']}\n"
    summary_output += f"Failed Lookups: {metadata['Failed Lookups']}\n\n"
    
    summary_output += "DISCOVERED ASSETS:\n"
    summary_output += f"- Domains: {metadata['Domains Found']}\n"
    summary_output += f"- IP Addresses: {metadata['IPs Found']}\n\n"
    
    if metadata['Unique Organizations']:
        summary_output += "ORGANIZATIONS:\n"
        for org in metadata['Unique Organizations']:
            summary_output += f"- {org}\n"
        summary_output += "\n"
        
    if metadata['Unique ASNs']:
        summary_output += "ASNs:\n"
        for asn in metadata['Unique ASNs']:
            summary_output += f"- {asn}\n"
        summary_output += "\n"
        
    if metadata['Countries']:
        summary_output += "GEOGRAPHIC DISTRIBUTION:\n"
        for country in metadata['Countries']:
            summary_output += f"- {country}\n"
        summary_output += "\n"
        
    if metadata['Open Ports']:
        summary_output += "EXPOSED SERVICES (OPEN PORTS):\n"
        for port in sorted(metadata['Open Ports']):
            service = get_common_service_name(port)
            summary_output += f"- Port {port}: {service}\n"
        summary_output += "\n"
        
    summary_output += "RECOMMENDATIONS:\n"
    summary_output += "1. Verify all discovered assets are authorized and properly secured\n"
    summary_output += "2. Check exposed services for unnecessary exposure and outdated versions\n"
    summary_output += "3. Consider implementing egress filtering where appropriate\n"
    summary_output += "4. Review organization information disclosure in public records\n"
    summary_output += "\n======= END OF SUMMARY REPORT =======\n"

    # Save formatted output, JSON results, and CSV
    with open(formatted_file, 'w') as f:
        f.write(formatted_output)
        
    with open(json_file, 'w') as f:
        json.dump(complete_results, f, indent=4)
        
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)
        writer.writerows(csv_rows)
        
    with open(summary_file, 'w') as f:
        f.write(summary_output)
    
    # Generate verification commands
    generate_verification_commands(results, verification_file, debug)

    print(f"Detailed results saved to: {formatted_file}")
    print(f"JSON results saved to: {json_file}")
    print(f"CSV results saved to: {csv_file}")
    print(f"Summary report saved to: {summary_file}")
    print(f"Verification commands saved to: {verification_file}")
    
    if debug:
        print(f"[DEBUG] Results saved to {output_dir} successfully.")


# Function to open Firefox with Shodan search queries
def open_firefox_queries(targets, debug=False):
    for target in targets:
        if is_ip(target):  # Check if the target is an IP
            query = f"https://www.shodan.io/host/{target}"  # Use host lookup URL for IPs
        else:
            query = f"https://www.shodan.io/domain/{target}"  # Use domain lookup URL for domains
        if debug:
            print(f"[DEBUG] Opening: {query}")
        subprocess.Popen(['firefox', query])  # Open Firefox with the query
        time.sleep(2)  # Wait for 2 seconds before opening the next tab


# Main function to handle arguments and run appropriate lookups
def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Shodan Search Tool for External Attack Surface Mapping.\n\nExample usage:\n'
                    'python sho_dane.py -t targets.txt -o results_dir -E -A\n\n'
                    'This tool performs Shodan lookups and enhanced discovery for a list of IPs or domains and saves comprehensive reports in the specified output directory.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--targets', help='Path to the file containing the list of IPs/domains/organizations')
    parser.add_argument('-s', '--single-target', help='Specify a single domain, IP address, or organization for lookup')
    parser.add_argument('-H', '--host', action='store_true', help='Perform Shodan host lookups for IP addresses')
    parser.add_argument('-D', '--dns', action='store_true', help='Perform DNS lookups for domains')
    parser.add_argument('-E', '--enhanced', action='store_true', help='Enable enhanced discovery using CT logs and other reliable techniques')
    parser.add_argument('-A', '--asn-lookup', action='store_true', help='Enable ASN lookup for organizations in target list')
    parser.add_argument('-R', '--reverse-dns', action='store_true', help='Perform reverse DNS lookups on discovered IPs')
    parser.add_argument('-b','--help-me-im-poor', action='store_true', help='Open Firefox tabs with Shodan queries for each target without using the API')
    parser.add_argument('-o', '--output', help='Output directory to save the results', default='shodan_results')
    parser.add_argument('-V', '--verification', action='store_true', help='Generate verification commands for discovered assets')
    parser.add_argument('-T', '--tools', action='store_true', help='Generate tool-friendly output files')
    parser.add_argument('--full-data', action='store_true', help='Get full data from Shodan API (uses more credits)')
    parser.add_argument('--batch-size', type=int, default=10, help='Number of targets to process in each batch (default: 10)')
    parser.add_argument('--batch-delay', type=int, default=2, help='Delay in seconds between batches to avoid rate limits (default: 2)')
    parser.add_argument('--debug', action='store_true', help='Enable debug messages for troubleshooting')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # Process targets
    if args.targets:
        print("[INFO] Processing target list.")
        targets = process_target_list(args.targets, debug=args.debug)
    elif args.single_target:
        print(f"[INFO] Single target provided: {args.single_target}")
        targets = [args.single_target]
    else:
        print("Error: You must specify a target file or single target.")
        return
    
    # Categorize targets by type for appropriate processing
    ip_targets = []
    domain_targets = []
    org_targets = []
    
    for target in targets:
        if is_ip(target) or is_cidr(target) or is_ip_range(target):
            ip_targets.append(target)
        elif '.' in target and not target.startswith(' '):  # Basic domain check
            domain_targets.append(target)
        else:
            # Assume anything that's not an IP/CIDR or domain is an organization name
            org_targets.append(target)
    
    if args.debug:
        print(f"[DEBUG] Categorized targets: {len(ip_targets)} IPs/CIDRs, {len(domain_targets)} domains, {len(org_targets)} organizations")
    
    # Expand any IP ranges in the targets
    if ip_targets:
        ip_targets = process_ip_ranges(ip_targets, debug=args.debug)
    
    # Credit usage estimation and warning
    total_estimated_credits = 0
    if args.host:
        host_credits = len(ip_targets)
        total_estimated_credits += host_credits
        print(f"[INFO] Host lookups for {len(ip_targets)} IPs will use approximately {host_credits} credits")
    
    if args.dns:
        base_domains = deduplicate_domains(domain_targets, debug=args.debug)
        dns_credits = len(base_domains)
        if args.enhanced and not args.full_data:
            # When enhanced is on but full_data is off, we still use CT logs but only query base domains
            print(f"[INFO] DNS lookups for {len(base_domains)} domains will use approximately {dns_credits} credits")
            print(f"[INFO] CT log mining will be used for subdomain discovery (no additional Shodan credits)")
        elif args.enhanced and args.full_data:
            # When both enhanced and full_data are on, we query all discovered domains
            ct_domains_count = 0
            for domain in base_domains:
                ct_domains = query_certificate_logs(domain, args.debug)
                ct_domains_count += len(ct_domains) if ct_domains else 0
            enhanced_dns_credits = dns_credits + ct_domains_count
            total_estimated_credits += enhanced_dns_credits
            print(f"[INFO] Enhanced DNS lookups could use up to {enhanced_dns_credits} credits")
        else:
            total_estimated_credits += dns_credits
            print(f"[INFO] DNS lookups for {len(base_domains)} domains will use approximately {dns_credits} credits")
    
    print(f"[INFO] Total estimated credit usage: {total_estimated_credits}")
    
    # Perform ASN lookups for organizations if requested
    if args.asn_lookup and org_targets:
        additional_targets = []
        
        for org in org_targets:
            print(f"[INFO] Looking up ASNs for organization: {org}")
            asn_info = get_asn_info(org, debug=args.debug)
            if asn_info:
                for asn in asn_info:
                    print(f"[INFO] Found ASN {asn['asn']}: {asn['name']}")
                    if 'prefixes' in asn:
                        for prefix in asn['prefixes']:
                            print(f"[INFO] Found CIDR block: {prefix['prefix']}")
                            additional_targets.append(prefix['prefix'])
        
        # Add ASN-discovered targets to the IP targets list
        if additional_targets:
            print(f"[INFO] Adding {len(additional_targets)} CIDR blocks from ASN lookup")
            ip_targets.extend(additional_targets)
            ip_targets = process_ip_ranges(ip_targets, debug=args.debug)
    
    # Combine all targets back together
    all_targets = ip_targets + domain_targets
    
    # Handle the --help-me-im-poor option (no config.ini needed)
    if args.help_me_im_poor:
        # Deduplicate domains (remove subdomains) for DNS if required
        if args.dns and domain_targets:
            deduped_domains = deduplicate_domains(domain_targets, debug=args.debug)
            open_firefox_queries(deduped_domains, debug=args.debug)

        # Resolve domains for host lookups if required
        if args.host and ip_targets:
            if not ip_targets:
                print("No valid IPs found to open in Firefox.")
                return
            open_firefox_queries(ip_targets, debug=args.debug)

        return  # Exit after opening tabs

    # For host or DNS lookups, the config.ini is required
    if args.host or args.dns:
        try:
            API_KEY = get_shodan_api_key(debug=args.debug)
            api = shodan.Shodan(API_KEY)
        except FileNotFoundError as e:
            print(e)
            return

    results = {}
    success_count = 0
    error_count = 0
    
    # Process targets in batches to prevent rate limiting
    batch_size = args.batch_size
    batch_delay = args.batch_delay

    # Host lookups with batching
    if args.host and ip_targets:
        print("[INFO] Performing host lookups...")
        ips = resolve_and_deduplicate_ips(ip_targets, debug=args.debug)
        
        # Process in batches
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i+batch_size]
            print(f"[INFO] Processing batch {i//batch_size + 1}/{(len(ips) + batch_size - 1)//batch_size} ({len(batch)} IPs)")
            
            batch_results, batch_success, batch_error = shodan_host_lookups(
                batch, api, debug=args.debug, min_credits=not args.full_data
            )
            
            results.update(batch_results)
            success_count += batch_success
            error_count += batch_error
            
            # Delay between batches to avoid rate limiting
            if i + batch_size < len(ips):
                print(f"[INFO] Waiting {batch_delay} seconds before next batch...")
                time.sleep(batch_delay)

    # DNS lookups with optional enhanced discovery and batching
    if args.dns and domain_targets:
        print("[INFO] Performing DNS lookups...")
        
        # Use base domains to save credits unless full data is requested
        if args.full_data:
            domains_to_process = domain_targets
        else:
            domains_to_process = deduplicate_domains(domain_targets, debug=args.debug)
        
        # Process in batches
        for i in range(0, len(domains_to_process), batch_size):
            batch = domains_to_process[i:i+batch_size]
            print(f"[INFO] Processing domain batch {i//batch_size + 1}/{(len(domains_to_process) + batch_size - 1)//batch_size} ({len(batch)} domains)")
            
            batch_results, batch_success, batch_error = shodan_dns_lookups(
                batch, api, debug=args.debug, 
                enhanced=args.enhanced, 
                min_credits=not args.full_data
            )
            
            results.update(batch_results)
            success_count += batch_success
            error_count += batch_error
            
            # Delay between batches to avoid rate limiting
            if i + batch_size < len(domains_to_process):
                print(f"[INFO] Waiting {batch_delay} seconds before next batch...")
                time.sleep(batch_delay)
    
    # Perform reverse DNS lookups if requested
    if args.reverse_dns and results:
        print("[INFO] Performing reverse DNS lookups on discovered IPs...")
        ip_targets = []
        
        # Extract all IPs from results
        for target, data in results.items():
            if is_ip(target, debug=args.debug):
                ip_targets.append(target)
            
            # Also check if there are IPs in the DNS records
            if 'DNS Records' in data and isinstance(data['DNS Records'], dict):
                for record_type, records in data['DNS Records'].items():
                    if record_type in ['A', 'AAAA'] and isinstance(records, list):
                        for record in records:
                            if 'value' in record and is_ip(record['value'], debug=args.debug):
                                ip_targets.append(record['value'])
        
        if ip_targets:
            print(f"[INFO] Found {len(ip_targets)} IPs for reverse DNS lookup")
            reverse_dns_results = reverse_dns_lookup(ip_targets, debug=args.debug)
            
            # Add reverse DNS results to the main results
            for ip, hostname in reverse_dns_results.items():
                if ip in results:
                    results[ip]['Reverse DNS'] = hostname
                    if hostname and hostname not in results:
                        # Add the hostname as a new domain target if not already in results
                        results[hostname] = {
                            'Domain': hostname,
                            'Resolved IP': ip,
                            'Source': 'Reverse DNS Lookup',
                            'Credit Usage': '0 credits (passive)'
                        }
                        success_count += 1
                        print(f"[INFO] Added new domain from reverse DNS: {hostname}")

     # Save results
    if results:
        save_results_to_directory(results, args.output, success_count, error_count, args.host, args.dns, debug=args.debug)
        
        # Generate tool-friendly output files if requested
        if args.tools:
            print(f"[INFO] Generating tool-friendly output files...")
            ip_targets, domain_targets, all_targets = generate_tool_output(results, args.output, debug=args.debug)
        
        print("\n[INFO] Attack surface mapping complete.")
        print(f"[INFO] Discovered {len(results)} targets.")
        print(f"[INFO] All reports saved to {args.output} directory.")
        
        # Add some guidance for next steps
        print("\nSUGGESTED NEXT STEPS:")
        print("1. Review the summary report for a high-level overview of the attack surface")
        print("2. Examine exposed services (open ports) for potential vulnerabilities")
        print("3. Verify all discovered domains and IPs belong to your target")
        
        # Get the verification file path using the report prefix format used in save_results_to_directory
        report_prefix = datetime.now().strftime("%Y%m%d-%H%M%S")
        verification_file = os.path.join(args.output, f'{report_prefix}_verification_commands.sh')
        
        if args.tools:
            print("4. Use the generated tool-friendly files with nmap or other security tools")
            if args.verification:
                print("5. Run the verification script to validate findings")
                print(f"   chmod +x {verification_file}")
                print(f"   {verification_file}")
        elif args.verification:
            print("4. Run the verification script to validate findings")
            print(f"   chmod +x {verification_file}")
            print(f"   {verification_file}")
        else:
            print("4. Use the CSV output for import into other security tools")
            print("5. For more targeted output files, run with --tools flag")
    else:
        print("\n[WARNING] No results were found. Try adjusting your search parameters or targets.")


# Entry point for the script
if __name__ == "__main__":
    main()