#!/usr/bin/env python3

# by TheTechromancer

import re
import csv
import sys
import json
import argparse
import ipaddress
from time import sleep

# services to look for
try:
    default_controls = dict()
    service_count = 0
    with open('services.json') as f:
        for item in json.load(f).items():
            fname, sname = item
            if not fname.startswith('_'):
                default_controls[fname] = sname
                service_count += 1

    print('[+] Successfully loaded {:,} services from "services.json"'.format(service_count))

except:
    default_controls = {

        # friendly name     # string to look for in services (case-insensitive)
        "Symantec":         "SYMANTEC ENDPOINT PROTECTION",
        "Altiris":          "SYMANTEC MANAGEMENT AGENT",
        "Malwarebytes":     "MALWAREBYTES"
    }
    print('[+] Failed to load services from "services.json", falling back to default')
    sleep(1)


class ControlsAnalysis:

    # for removing color in output
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def __init__(self, cme_logs, controls=default_controls):

        self.controls = {h[0]: HostBasedControl(*h) for h in controls.items()}

        self.count = 0
        self.total_servers = 0
        self.total_workstations = 0
        self.total_undetermined = 0
        self.total_executed = 0
        self.hosts = dict()

        self._parse_files(cme_logs)


    def _parse_files(self, cme_logs):

        lines = []

        for log in cme_logs:
            try:
                with open(log) as f:
                    lines += [[self.ansi_escape.sub('', l.upper()) for l in line.strip().split()] for line in f.readlines()]

            except FileNotFoundError:
                sys.stderr.write('[!] Error opening file: {}\n'.format(str(log)))
                continue

        for line in lines:
            self._parse_cme_line(line)

        self.count_controls()



    def _parse_cme_line(self, line):

        try:

            if '445' in line:
                ip = str(ipaddress.IPv4Address(line[1]))
                hostname = line[3]
                if hostname == 'NONE':
                    hostname = ''

                try:
                    self.hosts[ip].hostnames.add(hostname)
                except KeyError:
                    self.hosts[ip] = Host(hostname)
                    self.hosts[ip].ip = ip

                host = self.hosts[ip]

                line = ' '.join(line)
                host.get_role(line)

                if '[+] EXECUTED COMMAND' in line and not host.command_executed:
                    self.total_executed += 1
                    host.command_executed = True
                else:
                    for control in self.controls.values():
                        if control.sname in line:
                            host.controls.add(control.fname)

        except (IndexError, ipaddress.AddressValueError):
            return


    def count_controls(self):

        for host in self.hosts.values():

            if host.command_executed:

                if host.role == 'Workstation':
                    self.total_workstations += 1
                elif host.role == 'Server':
                    self.total_servers += 1
                else:
                    self.total_undetermined += 1

                for c in host.controls:

                    control = self.controls[c]

                    control.total_count += 1
                    if host.role == 'Workstation':
                        control.workstation_count += 1
                    elif host.role == 'Server':
                        control.server_count += 1
                    else:
                        control.undetermined_count += 1


    def print_stats(self):

        report = []

        print('\nHosts Analyzed:   {:,}\n'.format(self.total_executed))
        print('     {:<20}{:<20}{:<20}{:<20}{:<20}'.format( \
            'Service', 'Total', 'Workstations', 'Servers', 'Undetermined'))

        for control in self.controls.values():
            report.append('     {:<20}{:<20}{:<20}{:<20}{:<20}'.format( \
                control.fname, \
                self._pretty_percent(control.total_count, self.total_executed), \
                self._pretty_percent(control.workstation_count, self.total_workstations, ), \
                self._pretty_percent(control.server_count, self.total_servers), \
                self._pretty_percent(control.undetermined_count, self.total_undetermined)
            ))
            #'{:.1f}%'.format(control.total_count/self.total_executed*100), \

        print('=' * max([len(l) for l in report]))
        print('\n'.join(report))
        print('')


    @staticmethod
    def _pretty_percent(positive, total):

        try:
            percent = positive / total * 100
        except ZeroDivisionError:
            percent = 0

        return '{:,}/{:,} ({:.1f}%)'.format(positive, total, percent)


    def write_csv(self, csvfile):

        with open(str(csvfile), 'w', newline='') as f:

            csvfile = csv.DictWriter(f, fieldnames=['IP Address', 'Hostname', 'Role'] + list(self.controls.keys()))
            csvfile.writeheader()

            sorted_hosts = list(self.hosts.values())
            sorted_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))

            for host in sorted_hosts:
                if host.command_executed:
                    host_dict = host.to_dict(self.controls.values())
                    csvfile.writerow(host_dict)




class HostBasedControl:

    def __init__(self, fname, sname):

        # friendly name
        self.fname = fname
        # service keyword
        self.sname = sname

        self.total_count = 0
        self.server_count = 0
        self.workstation_count = 0
        self.undetermined_count = 0


    def __str__(self):

        return self.fname




class Host:

    unknown_os_re = re.compile(r'.+WINDOWS [0-9]{1,2}\.[0-9]{1} BUILD.+')

    def __init__(self, hostname=''):

        self.command_executed = False
        if hostname:
            self.hostnames = set([hostname])
        else:
            self.hostnames = set()
        self.controls = set()

        self.role = 'Unknown'


    def get_role(self, line):

        if self.role == 'Unknown' and 'WINDOWS' in line:

            line = line.upper()

            if 'WINDOWS SERVER' in line:
                self.role = 'Server'
            elif not self.unknown_os_re.match(line):
                self.role = 'Workstation'

        return self.role


    def to_dict(self, controls):

        d = dict()

        d['IP Address'] = self.ip
        d['Hostname'] = ', '.join(self.hostnames)
        d['Role'] = self.role

        for control in controls:
            if self.command_executed:
                if control.fname in self.controls:
                    d[control.fname] = 'Yes'
                else:
                    d[control.fname] = 'No'
            else:
                d[control.fname] = 'Unknown'

        return d




if __name__ == '__main__':

    def example_command():

        keywords = set()
        for phrase in [c.lower().split() for c in default_controls.values()]:
            keywords.update(phrase)

        print('\n[+] First, Generate CrackMapExec output by running:')
        print('     # cme smb <host_list> -u <username> -p <password> \
-x \'sc query | findstr /i "{}"\' | tee output.txt'.format(' '.join(keywords)))
        print('[+] Then, parse the output:')
        print('     # ./parse_cme.py *.txt')

    parser = argparse.ArgumentParser("Generate stats from CrackMapExec logs")
    parser.add_argument('cme_logs', nargs='+',  help='CrackMapExec log(s) to parse', metavar='CME_LOG')
    parser.add_argument('-w', '--write-csv',    help='Write analysis to CSV file', metavar='CSV_FILE')

    try:
        if len(sys.argv) < 2:
            parser.print_help()
            example_command()
            exit(1)

        options = parser.parse_args()

        c = ControlsAnalysis(options.cme_logs)
        c.print_stats()

        if options.write_csv:
            c.write_csv(options.write_csv)
            print('[+] CSV file written to {}'.format(str(options.write_csv)))

    except argparse.ArgumentError:
        parser.print_help()
        example_command()
    except KeyboardInterrupt:
        sys.stderr.write('[!] Interrupted\n')
        exit(1)
