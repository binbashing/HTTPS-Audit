# HTTPS-Audit

A simple python script to audit a subnet or host for HTTPS details.

## Dependencies
* OpenSSL
* NMAP
* unicodecsv

## Usage
```
usage: https_audit.py [-h] -s SUBNET [-p PORT] [-o OUTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -s SUBNET, --subnet SUBNET
                        Host or subnet to scan
  -p PORT, --port PORT  Port Number
  -o OUTFILE, --outfile OUTFILE
                        Output File
```
#### Examples
```
# Scan local subnet and save results to https-scan.csv
python3 https-audit.py -s 192.168.1.0/24 -o https-scan.csv

# Scan site and save results to https-audit-www-foo-com.csv
python3 https-audit.py -s www.foo.com
```

#### Example Output

 IP | Web Server | Web Server Version | CN | Issued | Expires | Issuer
---- | ------------ | -------------------- | ---- | --------- | ----------- | -------- | --------
192.30.253.113 | | | github.com | 2018-05-08 00:00:00 | 2020-06-03 12:00:00 | DigiCert SHA2 Extended Validation Server CA
