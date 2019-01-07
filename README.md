 # parse-crackmapexec

Generates statistics based on output from CrackMapExec.  Ideal for enumeration of host-based controls.

## Features:
* Automatic deduplication
* Automatic handling of colorized output (no manual copy-pasting)
* Customizable search strings (see services.json)
* Analysis of host-based controls by percentage, broken down by servers and workstations
* Export details to CSV


## Usage:
~~~
$ ./parse_cme.py
usage: Generate stats from CrackMapExec logs [-h] [-w CSV_FILE]
                                             CME_LOG [CME_LOG ...]

positional arguments:
  CME_LOG               CrackMapExec log(s) to parse

optional arguments:
  -h, --help            show this help message and exit
  -w CSV_FILE, --write-csv CSV_FILE
                        Write analysis to CSV file

[+] First, Generate CrackMapExec output by running:
     # cme smb <host_list> -u <username> -p <password> -x 'sc query | findstr /i "symantec malwarebytes"' | tee output.txt
[+] Then, parse the output:
     # ./parse_cme.py *.txt
~~~


## Example:
Run CrackMapExec
~~~
# cme smb <host_list> -u <username> -p <password> -x 'sc query | findstr /i "symantec malwarebytes"'
~~~
Parse output from multiple files and write results to CSV file
~~~
$ ./parse_cme.py output1.txt output2.txt -w test0.csv

Hosts Analyzed:   652

     Service             Total               Workstations        Servers             Undetermined        
=========================================================================================================
     Symantec            624/652 (95.7%)     536/557 (96.2%)     16/19 (84.2%)       72/76 (94.7%)
     Altiris             554/652 (85.0%)     533/557 (95.7%)     13/19 (68.4%)       8/76 (10.5%)
     Malwarebytes        9/652 (1.4%)        3/557 (0.5%)        6/19 (31.6%)        0/76 (0.0%)
~~~