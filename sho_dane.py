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


# Resolve and deduplicate IP addresses for host lookups (keep subdomains)
def resolve_and_deduplicate_ips(domains, debug=False):
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
    # Deduplicate IP addresses
    unique_ips = set(resolved_ips.values()) - {None}
    if debug:
        print(f"[DEBUG] Deduplicated IPs for Host Lookup: {unique_ips}")
    return list(unique_ips)


# Function to perform DNS lookups for domains
def shodan_dns_lookups(domains, api, debug=False):
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
def shodan_host_lookups(ips, api, debug=False):
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


# Save results to a local directory with specified output files for host and DNS queries
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
        description='Shodan Search Tool for IPs and Domains.\n\nExample usage:\n'
                    'python shodan_search.py -t targets.txt -o results_dir\n\n'
                    'This tool performs Shodan lookups for a list of IPs or domains and saves results in the specified output directory.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--targets', help='Path to the file containing the list of IPs/domains')
    parser.add_argument('-s', '--single-target', help='Specify a single domain or IP address for lookup')
    parser.add_argument('-H', '--host', action='store_true', help='Perform Shodan host lookups for IP addresses')
    parser.add_argument('-D', '--dns', action='store_true', help='Perform DNS lookups for domains')
    parser.add_argument('-b','--help-me-im-poor', action='store_true', help='Open Firefox tabs with Shodan queries for each target without using the API')
    parser.add_argument('-o', '--output', help='Output directory to save the results', default='shodan_results')
    parser.add_argument('--debug', action='store_true', help='Enable debug messages for troubleshooting')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # Handle the --help-me-im-poor option (no config.ini needed)
    if args.help_me_im_poor:
        # Use single target if specified, otherwise use targets from file
        if args.single_target:
            targets = [args.single_target]
        elif args.targets:
            targets = process_target_list(args.targets, debug=args.debug)
        else:
            print("Error: You must specify either a target file or a single target for the --help-me-im-poor option.")
            return

        # Deduplicate domains (remove subdomains) for DNS if required
        if args.dns:
            deduped_domains = deduplicate_domains([t for t in targets if not is_ip(t, debug=args.debug)], debug=args.debug)
            open_firefox_queries(deduped_domains, debug=args.debug)

        # Resolve domains for host lookups if required
        if args.host:
            ips = resolve_and_deduplicate_ips(targets, debug=args.debug)
            if not ips:
                print("No valid IPs found to open in Firefox.")
                return
            open_firefox_queries(ips, debug=args.debug)

        return  # Exit after opening tabs

    # For host or DNS lookups, the config.ini is required
    if args.host or args.dns:
        try:
            API_KEY = get_shodan_api_key(debug=args.debug)
            api = shodan.Shodan(API_KEY)
        except FileNotFoundError as e:
            print(e)
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
        ips = resolve_and_deduplicate_ips(targets, debug=args.debug)
        host_results, host_success_count, host_error_count = shodan_host_lookups(ips, api, debug=args.debug)
        results.update(host_results)
        success_count += host_success_count
        error_count += host_error_count

    # DNS lookups
    if args.dns:
        print("[INFO] Performing DNS lookups...")
        deduped_domains = deduplicate_domains([t for t in targets if not is_ip(t, debug=args.debug)], debug=args.debug)
        dns_results, dns_success_count, dns_error_count = shodan_dns_lookups(deduped_domains, api, debug=args.debug)
        results.update(dns_results)
        success_count += dns_success_count
        error_count += dns_error_count

    # Save results
    save_results_to_directory(results, args.output, success_count, error_count, args.host, args.dns, debug=args.debug)


# Entry point for the script
if __name__ == "__main__":
    main()
