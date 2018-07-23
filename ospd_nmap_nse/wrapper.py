# -*- coding: utf-8 -*-
# Description:
# Setup for the OSP nmap-nse Server
#
# Authors:
# Juan Jose Nicola <juan.nicola@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

import re
import string
import subprocess
import nmap
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as secET

from os import listdir
from itertools import product
from os.path import isfile, join, dirname, basename

from ospd.ospd import OSPDaemon, OSPDError
from ospd.misc import main as daemon_main
from ospd_nmap_nse import __version__


OSPD_DESC = """
This scanner runs the NSE scripts of the tool 'nmap' to scan target hosts.

This tool is availble for most operating systems and identifies open ports,
probes the services, operating systems and even can run more sophisticated
detection routines.

For more details about nmap see the nmap homepage:
http://nmap.org/

The current version of ospd-nmap-nse is a very simple one. It executes the
selected script categories through the NMAP Script Engine (NSE).
"""

BOOL_OPT_DIC = {
    'allhoston': '-Pn',
    'pingscan': '-sn',
    'servdet': '-sV',
}
BOOL_CATEGORIES_DIC = {
    'auth': 'auth',
    'broadcast': 'broadcast',
    'brute': 'brute',
    'default': 'default',
    'discovery': 'discovery',
    'dos': 'dos',
    'exploit': 'exploit',
    'external': 'external',
    'fuzzer': 'fuzzer',
    'intrusive': 'intrusive',
    'malware': 'malware',
    'safe': 'safe',
    'version': 'version',
    'vuln': 'vuln',
}

OSPD_PARAMS = {
    'dumpxml': {
        'type': 'boolean',
        'name': 'Dump the XML output of nmap',
        'default': 0,
        'mandatory': 0,
        'description': 'Whether to create a log result ' +
                       'with the raw XML output of nmap.',
    },
    'allhoston': {
        'type': 'boolean',
        'name': 'All hosts as online',
        'default': 0,
        'mandatory': 0,
        'description': 'Treat all hosts as online.',
    },
    'servdet': {
        'type': 'boolean',
        'name': 'Service detection.',
        'default': 0,
        'mandatory': 0,
        'description': 'Enable service detection.',
    },
    'pingscan': {
        'type': 'boolean',
        'name': 'Ping Scan',
        'default': 0,
        'mandatory': 0,
        'description': 'Disable port scan.',
    },
    'auth': {
        'type': 'boolean',
        'name': 'Auth Category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'broadcast': {
        'type': 'boolean',
        'name': 'Broadcast category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'brute': {
        'type': 'boolean',
        'name': 'Brute category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'default': {
        'type': 'boolean',
        'name': 'Default category',
        'default': 1,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'discovery': {
        'type': 'boolean',
        'name': 'Discovery category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'dos': {
        'type': 'boolean',
        'name': 'Dos category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'exploit': {
        'type': 'boolean',
        'name': 'Exploit category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'external': {
        'type': 'boolean',
        'name': 'External category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'fuzzer': {
        'type': 'boolean',
        'name': 'Fuzzer category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'intrusive': {
        'type': 'boolean',
        'name': 'Intrusive category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'malware': {
        'type': 'boolean',
        'name': 'Malware category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'safe': {
        'type': 'boolean',
        'name': 'Safe category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'version': {
        'type': 'boolean',
        'name': 'Version category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
    'vuln': {
        'type': 'boolean',
        'name': 'Vuln category',
        'default': 0,
        'mandatory': 0,
        'description': 'Run all scripts in category.',
    },
}


class OSPDnmap_nse(OSPDaemon):

    """ Class for ospd-nmap daemon. """

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the ospd-nmap daemon's internal data. """
        super(OSPDnmap_nse, self).__init__(certfile=certfile, keyfile=keyfile,
                                           cafile=cafile)
        self.server_version = __version__
        self.scanner_info['name'] = 'nmap'
        self.scanner_info['version'] = ''  # achieved during self.check()
        self.scanner_info['description'] = OSPD_DESC
        for name, param in OSPD_PARAMS.items():
            self.add_scanner_param(name, param)
        self.load_nse_scripts()

    def process_scan_params(self, params):
        """ params is directly from the XML """
        for param in OSPD_PARAMS:
            if (param in BOOL_OPT_DIC or param in BOOL_CATEGORIES_DIC or
                    param in ['dumpxml', ]):
                continue
            if not params.get(param):
                raise OSPDError('Empty %s value' % param, 'start_scan')
        return params

    def check(self):
        """ Checks that nmap command line tool is found and is executable. """
        try:
            result = subprocess.check_output(['nmap', '-oX', '-'],
                                             stderr=subprocess.STDOUT)
        except OSError:
            # the command is not available
            return False

        if result is None:
            return False

        tree = secET.fromstring(result)
        if tree.tag != 'nmaprun':
            return False

        version = tree.attrib.get('version')
        if version == '':
            return False
        self.scanner_info['version'] = version

        return True

    def find_nse_scripts_path(self):
        """ Return the path to the nse script directory. """
        # Try with a possible path
        if isfile('/usr/share/nmap/scripts/script.db'):
            return '/usr/share/nmap/scripts/'

        args = ['find', '/', '-wholename', '*scripts/script.db*']
        process = subprocess.Popen(args, stdout=subprocess.PIPE)
        res = process.stdout.read().decode()
        if isfile(res.strip('\n')):
            return dirname(res)

    def get_custom_vt_as_xml_str(self, custom):
        """ Create a string representation of the XML object from the
        custom data object.
        @return: XML object as string for custom data.
        """
        return custom

    def load_nse_scripts(self):
        """ Parse the nse scripts and load them into memory. """
        nmap_script_dir = self.find_nse_scripts_path()
        if nmap_script_dir is None:
            return 2

        strings = ('author =', 'categories =', 'license =')
        scripts = [join(nmap_script_dir, f)
                   for f in listdir(nmap_script_dir)
                   if isfile(join(nmap_script_dir, f)) and
                   f[-4:] == '.nse']

        for script in scripts:
            file = open(script, 'r')
            vt = ET.Element('vt')
            filename = basename(script)
            vt.set('vt_id', filename)
            custom_str = ''
            for patt, line in product(strings, file):
                if patt in line:
                    elem = line.split('=')
                    if len(elem) > 1:
                        printable = string.printable
                        custom_out = ''.join(filter(lambda x: x in
                                                    printable, elem[1]))
                        re_aux = re.sub("[<>\n]", '', custom_out)
                        custom_str += '<{0}>{1}</{0}>'.format(elem[0], re_aux)

            if custom_str != '' and custom_str is not None:
                self.add_vt(basename(script), name=basename(script),
                            custom=custom_str)

    def add_parsed_results(self, scan_id, target, hosts, result):
        """ Add the results of the scan.
        @param result: Dictionary containing the parsed results.
        @param nm:     The nmap object used to run the scan.
        """
        scripts = []
        ports = []
        for host in hosts:
            try:
                scripts = result['scan'][host]['hostscript']
            except KeyError:
                None
            for script in scripts:
                self.add_scan_log(scan_id, host=host, name=('NSE ' +
                                                              script['id']),
                                  value=script['output'])

            try:
                ports = result['scan'][host]['tcp']
            except KeyError:
                None

            for port in ports:
                if ('script' in ports[port]):
                    for script in ports[port]['script'].keys():
                        self.add_scan_log(scan_id, host=host, name=('NSE ' +
                                                                      script),
                                          value=ports[port]['script'][script],
                                          port='{0}/tcp'.format(port))
                else:
                    self.add_scan_log(scan_id, host=host,
                                      name='Nmap port detection',
                                      port='{0}/tcp'.format(port))

    @staticmethod
    def process_vts(vts):
        """ Add single scripts and script's arguments. """
        script = []
        args = []

        for memb in vts.items():
            script.append(memb[0])
            for i in memb[1].items():
                param = '{0}={1}'.format(i[0], i[1]['value'])
                args.append(param)

        separ = ','
        script_list = separ.join(script)
        script_args = ''
        if args:
            script_args = separ.join(args)
        return script_list, script_args

    def exec_scan(self, scan_id, target):
        """ Starts the nmap scanner for scan_id scan. """

        ports = self.get_scan_ports(scan_id, target)
        options = self.get_scan_options(scan_id)
        dump = options.get('dumpxml')

        # Add default options to nmap command string, that is scan
        # for udp/tcp port and output in xml format.
        command_str = ['-sT', ]
        if ports and 'U' in ports:
            command_str.append('-sU')
        if ports == '':
            ports = None

        # Add all enabled options
        # All boole options
        for opt in BOOL_OPT_DIC:
            if options.get(opt):
                command_str.append(BOOL_OPT_DIC[opt])
                if opt == 'pingscan':
                    ports = None

        # Add categories
        categ = []
        for opt in BOOL_CATEGORIES_DIC:
            if options.get(opt):
                categ.append(BOOL_CATEGORIES_DIC[opt])

        # Add single VTs
        script_args = ''
        scripts = self.get_scan_vts(scan_id)
        if scripts:
            script_list, script_args = self.process_vts(scripts)
            categ.append(script_list)
        separ = ','
        categ_list = separ.join(categ)
        categ_list = '--script=' + categ_list
        command_str.append(categ_list)
        if script_args:
            script_args_str = "--script-args='{0}'".format(script_args)
            command_str.append(script_args_str)

        separ = ' '
        arg_list = separ.join(command_str)
        # Run Nmap
        result = None
        nm = nmap.PortScanner()
        try:
            result = nm.scan(hosts=target, ports=ports, arguments=arg_list)
        except nmap.PortScannerError as e:
            self.add_scan_error(scan_id, host=target,
                                value=('A problem occurred trying to '
                                       'execute "nmap": {0}.'. format(e)))
            return 2

        if result is None:
            message = "A problem occurred trying to execute 'nmap'."
            self.add_scan_error(scan_id, host=target, value=message)
            self.add_scan_error(scan_id, host=target,
                                value="The result of 'nmap' was empty.")
            return 2

        # If "dump" was set to True, then create a log entry with the dump.
        if dump == 1:
            self.add_scan_log(scan_id, host=target, name='Nmap dump',
                              value='Raw nmap output:\n\n%s' % result)

        # Create a general log entry about executing nmap
        # It is important to send at least one result, else
        # the host details won't be stored.
        summary = ('Nmap done at {0}; {1} IP address ({2} host up) scanned in {3} seconds'.format(
            nm.scanstats()['timestr'],
            nm.scanstats()['totalhosts'],
            nm.scanstats()['uphosts'],
            nm.scanstats()['elapsed'],))
        self.add_scan_log(scan_id, host=target, name='Nmap summary',
                          value=summary)

        self.add_parsed_results(scan_id, target, nm.all_hosts(), result)

        return 1


def main():
    """ OSP nmap main function. """
    daemon_main('OSPD - nmap wrapper', OSPDnmap_nse)
