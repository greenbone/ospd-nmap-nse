![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# ospd-nmap-nse

This is an OSP server implementation to allow GVM to remotely control
the `nmap` port scanner and use it to execute scripts using the Nmap Scripting
Engine (NSE).

Once running, you need to configure the Scanner for Greenbone Vulnerability
Manager, for example via the web interface Greenbone Security Assistant.
Then you can create scan tasks to use this scanner.

## Installation

### Requirements

Python 3 and later is supported.

Beyond the [ospd base library](https://github.com/greenbone/ospd) and the
`nmap` tool, `osp-nmap-nse` has dependecies on the follow Python package:

- `python-nmap`

There are no special installation aspects for this module beyond the general
installation guide for ospd-based scanners.

Please follow the general installation guide for ospd-based scanners:

  <https://github.com/greenbone/ospd/blob/master/doc/INSTALL-ospd-scanner>

## Usage

For executing `nmap`, a low privileged user account is sufficient for basic
operations. However, some details are only available with a high privileged
user account.

Apart from the above, are no special usage aspects for this module beyond the
generic usage guide.

Please follow the general usage guide for ospd-based scanners:

  <https://github.com/greenbone/ospd/blob/master/doc/USAGE-ospd-scanner>

### Examples

Starting all of the NSE scripts gainst a single host would be started like:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-nmap-nse.sock --xml="<start_scan target='192.168.10.133' ports='T:1-1024'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston><default>1</default><brute>1</brute></scanner_params></start_scan>"

Selecting a single NSE script (a VT), for example `address-info.nse`:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-nmap-nse.sock --xml="<start_scan target='127.0.0.1' ports='T:1-1024'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston></scanner_params><vts><vt id='address-info.nse' /></vts></start_scan>"

Selecting a single NSE script (a VT) and script arguments, for example
`smb-psexec.nse`:

    gvm-cli socket --sockpath /tmp/nmap-nse.sock --xml "<start_scan target='192.168.10.133' ports='445'><scanner_params><pingscan>0</pingscan><allhoston>0</allhoston><default>0</default></scanner_params><vts><vt id='smb-psexec'><vt_param name='smbuser'>msfadmin</vt_param><vt_param name='smbpass'>msfadmin</vt_param><vt_param name='config'>example</vt_param><vt_param name='host'>1.2.3.4</vt_param></vt></vts></start_scan>"

## Support

For any question on the usage of osp-nmap-nse please use the [Greenbone
Community Portal](https://community.greenbone.net/c/gse). If you found a
problem with the software, please [create an
issue](https://github.com/greenbone/osp-nmap-nse/issues) on GitHub. If you are
a Greenbone customer you may alternatively or additionally forward your issue
to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks
GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/osp-nmap-nse/pulls) on GitHub. Bigger
changes need to be discussed with the development team via the [issues section
at GitHub](https://github.com/greenbone/osp-nmap-nse/issues) first.

## License

Copyright (C) 2015-2018 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU General Public License v2.0 or later](COPYING).
