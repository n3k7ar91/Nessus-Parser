import argparse
import os
from ipaddress import IPv4Address
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
from lxml import etree
from tqdm import tqdm
from art import text2art

@dataclass
class Vulnerability:
    plugin_name: str
    risk_factor: str
    port: str
    hosts: Set[str] = field(default_factory=set)

def parse_nessus_report(report_file: str, risk_factors: Optional[List[str]]) -> Dict[str, Vulnerability]:
    """Parses a single Nessus report file."""
    try:
        tree = etree.parse(report_file)
        root = tree.getroot()
    except etree.XMLSyntaxError as e:
        print(f"Error parsing {report_file}: {e}")
        return {}

    vulnerabilities: Dict[str, Vulnerability] = {}
    report_hosts = list(root.findall('.//Report/ReportHost'))

    for report_host in report_hosts:
        host_name = report_host.get('name')
        for item in report_host.findall('ReportItem'):
            risk_factor = item.findtext('risk_factor', 'None')

            if risk_factors and risk_factor not in risk_factors:
                continue

            plugin_name = item.get('pluginName')
            port_number = item.get('port')

            if plugin_name not in vulnerabilities:
                vulnerabilities[plugin_name] = Vulnerability(
                    plugin_name=plugin_name,
                    risk_factor=risk_factor,
                    port=port_number
                )

            vulnerabilities[plugin_name].hosts.add(host_name)

    return vulnerabilities

def merge_vulnerabilities(all_vulnerabilities: List[Dict[str, Vulnerability]]) -> Dict[str, Vulnerability]:
    """Merges vulnerabilities from multiple reports."""
    merged: Dict[str, Vulnerability] = {}
    for report_vulnerabilities in all_vulnerabilities:
        for plugin_name, vuln in report_vulnerabilities.items():
            if plugin_name not in merged:
                merged[plugin_name] = vuln
            else:
                merged[plugin_name].hosts.update(vuln.hosts)
    return merged

def write_report(output_file: str, vulnerabilities: Dict[str, Vulnerability], retest: bool):
    """Writes the parsed vulnerability data to a file."""
    all_hosts: Set[str] = set()
    all_ports: Set[str] = set()

    with open(output_file, 'w') as outfile:
        sorted_vulns = sorted(vulnerabilities.values(), key=lambda v: (v.risk_factor, v.plugin_name))

        for vuln in sorted_vulns:
            if vuln.risk_factor == 'None':
                continue

            sorted_hosts = sorted(list(vuln.hosts), key=IPv4Address)
            all_hosts.update(vuln.hosts)
            if vuln.port != '0':
                all_ports.add(vuln.port)

            outfile.write(f"Vulnerability: {vuln.plugin_name}\n")
            outfile.write(f"Risk Factor: {vuln.risk_factor}\n")
            outfile.write(f"Port: {vuln.port}\n")
            outfile.write("Affected Hosts: ")
            outfile.write(', '.join(sorted_hosts) + "\n")
            outfile.write("\n" + 80 * '-' + "\n")

    print(f"\nFinal Report is saved in {output_file}!")

    if retest:
        sorted_ports = ", ".join(sorted(list(all_ports), key=int))
        sorted_all_hosts = ", ".join(sorted(list(all_hosts), key=IPv4Address))
        print(f"\nPorts for retest: {sorted_ports}")
        print(f"\nIPs for retest: {sorted_all_hosts}")

def file_extension_checker(file_path: str) -> str:
    """Checks if the file exists and has a .nessus extension."""
    if not os.path.isfile(file_path):
        raise argparse.ArgumentTypeError(f"{file_path} is not a file!")
    if not file_path.endswith('.nessus'):
        raise argparse.ArgumentTypeError(f"{file_path} is not a valid file extension!")
    return file_path

def main():
    """Main function to parse arguments and run the parser."""
    parser = argparse.ArgumentParser(description="Nessus Parser - Parse Nessus pentest report and output affected hosts per vulnerability.")
    parser.add_argument('-i', '--input', nargs='+', required=True, type=file_extension_checker, help='Path to the input pentest report file (.nessus format). Multiple files supported.')
    parser.add_argument('-o', '--output', required=True, help='Path to the output file where the parsed data will be saved.')
    parser.add_argument('-r', '--risk', nargs='*', type=str.capitalize, choices=['Low', 'Medium', 'High', 'Critical'], help='Optional filter for vulnerability risk factors.')
    parser.add_argument('--retest', action='store_true', help='Optional filter for showing specific IPs and ports needed for retest.')
    
    args = parser.parse_args()

    print(text2art("Nessus Parser"))

    all_vulnerabilities = []
    for report_file in tqdm(args.input, desc="Parsing Nessus files", unit="file"):
        report_vulnerabilities = parse_nessus_report(report_file, args.risk)
        all_vulnerabilities.append(report_vulnerabilities)

    merged_vulnerabilities = merge_vulnerabilities(all_vulnerabilities)
    write_report(args.output, merged_vulnerabilities, args.retest)

if __name__ == '__main__':
    main()
