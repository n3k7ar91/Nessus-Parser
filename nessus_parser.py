import sys
import xml.etree.ElementTree as ET
import argparse
from art import *
from tqdm import tqdm
import os 
from ipaddress import IPv4Address

def parse_nessus_report(report_files, output_file, risk_factors=None, retest=False):

    vulnerability_data = {}
    ports = set()
    hosts = set()

    for report_file in report_files:
        tree = ET.parse(report_file)
        root = tree.getroot()

        
        report_hosts = list(root.findall('.//Report/ReportHost'))

        for report_host in tqdm(report_hosts, desc=f"Parsing {report_file}!", unit="hosts"):
            host_name = report_host.get('name')

            for item in report_host.findall('ReportItem'):
                vulnerability = item.get('pluginName')
                risk_factor = item.findtext('risk_factor')
                port_number = item.get('port')

                if risk_factors and risk_factor not in risk_factors:
                    continue

                if vulnerability not in vulnerability_data:
                    vulnerability_data[vulnerability] = {
                        'hosts': [],
                        'risk_factor': risk_factor,
                        'port': port_number
                    }

                if host_name not in vulnerability_data[vulnerability]['hosts']:
                    vulnerability_data[vulnerability]['hosts'].append(host_name)
                    hosts.add(host_name)
                
                if port_number != '0':
                    ports.add(port_number)
               
        
    with open(output_file, 'w') as outfile:
        

        for vuln, data in vulnerability_data.items():
            if data['risk_factor'] != 'None':
                
                sorted_hosts = sorted(data['hosts'], key=lambda ip: IPv4Address(ip))
                
                outfile.write(f"Vulnerability: {vuln}\n")
                outfile.write(f"Risk Factor: {data['risk_factor']}\n")
                outfile.write(f"Port: {data['port']}\n")
                outfile.write("Affected Hosts: ")
                outfile.write(', '.join(sorted_hosts) + "\n")
                outfile.write("\n")
                outfile.write(80 * '-' + "\n")
                
    sorted_ports = ", ".join(sorted(ports, key=int))
    sorted_hosts = ", ".join(sorted(hosts, key=lambda ip: IPv4Address(ip)))

    print(f"\nFinal Report is saved in {output_file}!")
    
    if retest:
        print(f"\nPorts for retest: {sorted_ports}")
        print(f"\nIPs for retest: {sorted_hosts}")
    
    
  
    

    
def file_extension_checker(file_path):
    if not os.path.isfile(file_path):
        raise argparse.ArgumentTypeError(f"{file_path} is not a file!")
    if os.path.splitext(file_path)[1] not in ['.nessus']:
        raise argparse.ArgumentTypeError(f"{file_path} is not a valid file extension!")
    return file_path


def main():
    parser = argparse.ArgumentParser(description="Nessus Parser - Parse Nessus pentest report and output affected hosts per vulnerability.")
    parser.add_argument( '-i', '--input', nargs='+', required=True, type=file_extension_checker, help='Path to the input pentest report file (.nessus format). Multiple files supported. Should be separated with blank space.')
    parser.add_argument('-o', '--output', required=True, help='Path to the output file where the parsed data will be saved')
    parser.add_argument('-r', '--risk', nargs='*',type=str.capitalize, choices=['Low', 'Medium', 'High', 'Critical'], help='Optional filter for vulnerability risk factors (e.g., "High Critical"). Multiple values supported. Should be separated with blank space.')
    parser.add_argument('--retest', action='store_true', help='Optional filter for showing specific ips and ports needed for retest.')
    
    args = parser.parse_args()
    parse_nessus_report(args.input, args.output, args.risk, args.retest)

if __name__ == '__main__':
    print(text2art("Nessus Parser"))
    main()

