# nse-parse
Shell script for parsing vulnerable results from Nmap NSE scan output.

# Usage
```
./nse-parse.sh [input file] [--out-dir [dir]]
```
* **--out-dir [dir]** lets you optionally specify a directory to output results in. Results will be parsed into lists of IPs for each NSE and Vulnerable or Likely Vulnerable state (ex: smb-vuln-ms17-010-vulnerable-hosts.txt). By default, the files will be written in the current directory. If a specified directory does not exist, it will be created. If an existing directory is used, any existing files with the matching names will be appended to.

# Operation
Given a text file containing stdout/.nmap-format output for Nmap NSE scan results, the script will:
* Read each line of the file.
* Identify the current host with `grep 'Nmap scan report for'`.
* Identify the current NSE with `grep '|[ _][A-Za-z0-9-]*:'`.
* Identify the state with `grep 'State: VULNERABLE\|State: LIKELY VULNERABLE'`.
* After creating a temporary file formatted like `nse name,ip address,state`, the script will parse out Vulnerable and Likely Vulnerable IPs for each NSE and place them in the output directory.

# Example
```
# ./nse-parse.sh nmap-smb-vuln.txt --outdir test

=====================[ nse-parse.sh - Ted R (github: actuated) ]=====================

Parsing line 526 of 526 in nmap-smb-vuln.txt            

Parsing CSV results from temp file nsep-temp-2019-01-08-17-08.txt...

1 smb-vuln-cve2009-3103-vulnerable-hosts.txt
1 smb-vuln-ms06-025-vulnerable-hosts.txt
1 smb-vuln-ms08-067-likely-vulnerable-hosts.txt
6 smb-vuln-ms17-010-vulnerable-hosts.txt
3 smb-vuln-regsvc-dos-vulnerable-hosts.txt

Output files written in test/

=======================================[ fin ]=======================================

```
