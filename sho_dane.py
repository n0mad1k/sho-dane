import shodan
import configparser
import argparse
import argcomplete
import socket
import json
import os
import subprocess
import time
from datetime import datetime

# Read API key from config.ini file
def get_shodan_api_key(config_file='config.ini', debug=False):
    config = configparser.ConfigParser()
    config.read(config_file)
    if debug:
        print(f"[DEBUG] Reading API key from: {config_file}")
    return config['shodan']['api_key']

# Initialize the Shodan API using the key from config.ini
API_KEY = get_shodan_api_key()
api = shodan.Shodan(API_KEY)

# Function to resolve domain names to IP addresses
def resolve_domains_bulk(domains, debug=False):
    resolved_ips = {}
    for domain in domains:
        try:
            ip_address = socket.gethostbyname(domain)
            resolved_ips[domain] = ip_address
            if debug:
                print(f"[DEBUG] Resolved {domain} to {ip_address}")
        except socket.gaierror:
            if debug:
                print(f"[DEBUG] Could not resolve domain: {domain}")
            resolved_ips[domain] = None
    if debug:
        print(f"[DEBUG] Resolved IPs: {resolved_ips}")
    return resolved_ips

# Function to perform DNS lookups for domains
def shodan_dns_lookups(domains, debug=False):
    results = {}
    success_count = 0
    error_count = 0

    for domain in domains:
        try:
            if debug:
                print(f"[DEBUG] Looking up DNS information for: {domain}")
            dns_info = api.dns.domain_info(domain)
            success_count += 1
            results[domain] = {
                'Domain': domain,
                'Subdomains': dns_info.get('subdomains', []),
                'Tags': dns_info.get('tags', []),
                'DNS Records': dns_info.get('dns', {})
            }
        except shodan.APIError as e:
            error_count += 1
            if debug:
                print(f"[DEBUG] Error looking up DNS for {domain}: {e}")
            results[domain] = {"Error": str(e)}
    return results, success_count, error_count

# Function to perform Shodan host lookups for IPs
def shodan_host_lookups(ips, debug=False):
    results = {}
    success_count = 0
    error_count = 0

    unique_ips = list(set(ips))
    if debug:
        print(f"[DEBUG] Unique IPs for lookup: {unique_ips}")

    for ip in unique_ips:
        try:
            if debug:
                print(f"[DEBUG] Looking up IP: {ip}")
            host_info = api.host(ip, minify=False)
            success_count += 1
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
            }
        except shodan.APIError as e:
            error_count += 1
            if debug:
                print(f"[DEBUG] Error looking up {ip}: {e}")
            results[ip] = {"Error": str(e)}
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

# Helper function to check if a target is an IP address
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

# Save results to a local directory with separate formatted and JSON output files
# Save results to a local directory with specified output files for host and DNS queries
# Save results to a local directory with differentiated naming for host and DNS queries
def save_results_to_directory(results, output_dir, success_count, error_count, is_host_query, is_dns_query, debug=False):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Determine filenames based on query type
    if is_host_query:
        formatted_file = os.path.join(output_dir, 'shodan_host_query_quick_results.txt')
        json_file = os.path.join(output_dir, 'shodan_host_query_full_results.json')
    elif is_dns_query:
        formatted_file = os.path.join(output_dir, 'shodan_domain_query_quick_results.txt')
        json_file = os.path.join(output_dir, 'shodan_domain_query_full_results.json')

    # Formatted text output
    formatted_output = "\n======= Lookup Results =======\n\n"
    for target, data in results.items():
        if 'Error' in data:
            formatted_output += f"Domain/IP: {target}\n  Error: {data['Error']}\n"
        elif is_host_query and 'Location' in data:
            # Host Lookup Results
            formatted_output += f"Domain/IP: {target}\n"
            formatted_output += f"  IP: {data['IP']}\n"
            formatted_output += f"  Organization: {data['Organization']}\n"
            formatted_output += f"  ISP: {data['ISP']}\n"
            formatted_output += f"  ASN: {data['ASN']}\n"
            formatted_output += f"  Location: {data['Location'].get('City', 'N/A')}, {data['Location'].get('Country', 'N/A')}\n"
            formatted_output += f"  Last Update: {data.get('Last Update', 'N/A')}\n"
            formatted_output += f"  Open Ports: {data.get('Open Ports', [])}\n"
        elif is_dns_query:
            # DNS Lookup Results
            formatted_output += f"Domain/IP: {target}\n"
            formatted_output += f"  Subdomains: {data.get('Subdomains', 'N/A')}\n"
            formatted_output += f"  Tags: {data.get('Tags', 'N/A')}\n"
            formatted_output += f"  DNS Records: {data.get('DNS Records', 'N/A')}\n"
        formatted_output += "-" * 60 + "\n"

    metadata = {
        "Total Targets": len(results),
        "Successful Lookups": success_count,
        "Failed Lookups": error_count,
        "Generated On": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Description": "Shodan Lookup Results with detailed host and DNS information.",
    }
    complete_results = {
        "Metadata": metadata,
        "Results": results
    }

    # Save formatted output and JSON results
    with open(formatted_file, 'w') as f:
        f.write(formatted_output)
    with open(json_file, 'w') as f:
        json.dump(complete_results, f, indent=4)

    print(f"Formatted results saved to: {formatted_file}")
    print(f"JSON results saved to: {json_file}")
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
        description='Shodan Search Tool for IPs and Domains.\n\nExample:\n'
                    'python shodan_search.py -t targets.txt -o results_dir\n\n'
                    'The tool performs Shodan lookups for a list of IPs or domains and saves results in specified output directory.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--targets', help='Path to the file containing the list of IPs/domains')
    parser.add_argument('-s', '--single-target', help='Specify a single domain or IP address for lookup')
    parser.add_argument('-H', '--host', action='store_true', help='Perform Shodan host lookups for IP addresses')
    parser.add_argument('-D', '--dns', action='store_true', help='Perform DNS lookups for domains')
    parser.add_argument('--help-me-im-poor', action='store_true', help='Open Firefox tabs with Shodan queries for each target')
    parser.add_argument('-o', '--output', help='Output directory to save the results', default='shodan_results')
    parser.add_argument('--debug', action='store_true', help='Enable debug messages for troubleshooting')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # Handle the --help-me-im-poor option
    if args.help_me_im_poor:
        if args.targets:
            targets = process_target_list(args.targets, debug=args.debug)
            
            # Resolve domains to get their IPs
            resolved_ips = resolve_domains_bulk([t for t in targets if not is_ip(t, debug=args.debug)], debug=args.debug)

            # Combine direct IPs and resolved IPs from domains
            ips = list(set(resolved_ips.values()))  # Unique IPs from resolved domains
            ips += [t for t in targets if is_ip(t, debug=args.debug)]  # Add direct IPs
            ips = list(set(ips))  # Remove duplicates

            # Check if there are no valid IPs before proceeding
            if not ips:
                print("No valid IPs found to open in Firefox.")
                return
            
            # Open Firefox tabs with search queries for each target
            if args.dns:
                # If -D is passed, we only want to open domain queries
                open_firefox_queries([t for t in targets if not is_ip(t)], debug=args.debug)
            elif args.host:
                # If -H is passed, we want to open host queries
                open_firefox_queries(ips, debug=args.debug)
            
            return  # Exit after opening tabs
        else:
            print("Error: You must specify a target file for the --help-me-im-poor option.")
            return

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

    results = {}
    success_count = 0
    error_count = 0

    # Host lookups
    if args.host:
        print("[INFO] Performing host lookups...")
        ips = [t for t in targets if is_ip(t, debug=args.debug)]
        resolved_domains = [t for t in targets if not is_ip(t, debug=args.debug)]
        resolved_ips = resolve_domains_bulk(resolved_domains, debug=args.debug)
        ips.extend(resolved_ips.values())
        ips = list(set(filter(None, ips)))  # Deduplicate IPs
        host_results, host_success_count, host_error_count = shodan_host_lookups(ips, debug=args.debug)
        results.update(host_results)
        success_count += host_success_count
        error_count += host_error_count

    # DNS lookups
    if args.dns:
        print("[INFO] Performing DNS lookups...")
        domains = [t for t in targets if not is_ip(t, debug=args.debug)]
        dns_results, dns_success_count, dns_error_count = shodan_dns_lookups(domains, debug=args.debug)
        results.update(dns_results)
        success_count += dns_success_count
        error_count += dns_error_count

    # Save results
    save_results_to_directory(results, args.output, success_count, error_count, args.host, args.dns, debug=args.debug)

# Entry point for the script
if __name__ == "__main__":
    main()