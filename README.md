About OSPD-NMAP-NSE
-------------------

This is an OSP server implementation to allow GVM to remotely control
the nmap port scanner.

Once running, you need to configure the Scanner for Greenbone Vulnerability
Manager, for example via the web interface Greenbone Security Assistant.
Then you can create scan tasks to use this scanner.

OSPD-NMAP-NSE is licensed under GNU General Public License Version 2 or
any later version.  Please see file COPYING for details.

All parts of OSP-NMAP-NSE are Copyright (C) by Greenbone Networks GmbH
(see http://www.greenbone.net).


How to start OSPD-NMAP-NSE
--------------------------

There are no special usage aspects for this module
beyond the general usage guide.

Please follow the general usage guide for ospd-based scanners:

  https://github.com/greenbone/ospd/blob/master/doc/USAGE-ospd-scanner

Starting all of the NSE scripts gainst a single host would be started like:

$ gvm-cli socket --sockpath <prefix>/var/run/ospd-nmap-nse.sock --xml="<start_scan target='192.168.10.133' ports='T:1-1024'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston><default>1</default><brute>1</brute></scanner_params></start_scan>"

Selecting a single NSE script (a VT), for example "address-info.nse":

$ gvm-cli socket --sockpath <prefix>/var/run/ospd-nmap-nse.sock --xml="<start_scan target='127.0.0.1' ports='T:1-1024'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston></scanner_params><vts><vt id='address-info.nse' /></vts></start_scan>"

Selecting a single NSE script (a VT) and script arguments, for example "smb-psexec.nse":

$ gvm-cli socket --sockpath /tmp/nmap-nse.sock --xml "<start_scan target='192.168.10.133' ports='445'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston><default>0</default></scanner_params><vts><vt id='smb-psexec'><vt_param name='smbuser'>msfadmin</vt_param><vt_param name='smbpass'>msfadmin</vt_param><vt_param name='config'>example</vt_param><vt_param name='host'>1.2.3.4</vt_param></vt></vts></start_scan>"