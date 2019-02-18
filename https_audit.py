#!/usr/bin/python3

import nmap
import socket
import datetime
import argparse
from OpenSSL import SSL
import unicodecsv as csv


# Parse arguements
parser = argparse.ArgumentParser()
parser.add_argument('-s', '--subnet', help='Host or subnet to scan', required=True)
parser.add_argument('-p', '--port', help='Port Number', required=False, default='443')
parser.add_argument('-o', '--outfile', help='Output File', required=False, )
args = parser.parse_args()
subnet = (args.subnet)
port = (args.port)
if args.outfile:
    output_file = (args.outfile)
else:
    file_name = ['https-audit-', subnet.replace('.', '-').replace('/', '_'), '.csv']
    output_file = ''.join(file_name)


# Function to write data to CSV
def all_to_csv(input_list, out_file):
    keys = ['IP', 'Web Server', 'Web Server Version', 'CN', 'Issued', 'Expires', 'Issuer']
    with open(out_file, 'wb') as csv_file:
        dict_writer = csv.DictWriter(csv_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(input_list)


# Helper function to get certificate info
def get_cert_details(host, port):
    cert_dict = {}
    context = SSL.Context(SSL.SSLv23_METHOD)
    sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    sock.connect( (str(host) , port) )
    try:
        sock.send("\x00")
    except:
        return cert_dict
    get_peer_cert=sock.get_peer_certificate()
    cert_dict['CN'] = get_peer_cert.get_subject().CN
    cert_dict['Issuer'] = get_peer_cert.get_issuer().CN
    cert_dict['Expires'] = str(datetime.datetime.strptime(get_peer_cert.get_notAfter().decode('UTF-8'),'%Y%m%d%H%M%SZ'))
    cert_dict['Issued'] = str(datetime.datetime.strptime(get_peer_cert.get_notBefore().decode('UTF-8'),'%Y%m%d%H%M%SZ'))
    return cert_dict


# Function to scan subnet and get HTTPS info
def get_scan_details(subnet, port):
    nm = nmap.PortScanner()
    nm_results = nm.scan(subnet, port)
    pprint(nm_results)
    hosts = nm_results['scan']
    results = []
    for host in hosts:
        if hosts[host]['tcp'][int(port)]['state'] == 'open':
            cert_dict = get_cert_details(host, int(port))
            host_dict = {}
            host_dict['IP'] = host
            host_dict['Web Server'] = hosts[host]['tcp'][int(port)]['product']
            host_dict['Web Server Version'] = hosts[host]['tcp'][int(port)]['version']
            dict = {**cert_dict, **host_dict}
            results.append(dict)
    return results


def main():
    scan_results = get_scan_details(subnet, port)
    all_to_csv(scan_results, output_file)


main()
from pprint import pprint
10
