# SNMPede

SNMPede (SNMP + Centipede) is a pure Python wrapper script around the [PySNMP](https://www.pysnmp.com) project built to simplify attacking SNMP versions 1, 2c, and 3 across IPv4/6 systems. This tool works on any system supporting at least Python 3.9 such as most modern day Windows and Linux operating systems.

## Features

The following features are built into SNMPede:

- Authenticated Versioning (v1/2c/3)
- Spraying of Community Strings (v1/2c)
- Spraying usernames with NoAuthNoPriv (v3)
- Spraying username/password/protocol with AuthNoPriv (v3)
- Spraying username/passwords/protocols with AuthPriv (v3)
- BulkWalk of entire SNMP agents (v2c/v3)

```cmd
usage: snmpede.py [-h] [-c COMMUNITY] [-u USERNAME] [-p PASSWORD] [--bulkwalk] [--all] [-t TARGET] [-pt PORT]
                  [-i INTERFACE] [-eid ENGINE_ID] [-o OUTPUT] [-d {0,1,2}] [-to TIMEOUT] [-rt RETRIES] [-dl DELAY]
                  [-or OID_READ] [-tk TASKS]

A modern and intelligent approach to SNMP hacking

optional arguments:
  -h, --help            show this help message and exit

Modules:
  -c COMMUNITY, --community COMMUNITY
                        Login with a provided community string or line-delimited file
  -u USERNAME, --username USERNAME
                        Login with a username or line-delimited file
  -p PASSWORD, --password PASSWORD
                        Login with a password or line-delimited file
  --bulkwalk            Collect as much information as possible
  --all                 CAUTION: Use all above modules and default login dictionaries

I/O Arguments:
  -t TARGET, --target TARGET
                        Singular hostname or IPv4/IPv6 address or file containing line-delimited targets
  -pt PORT, --port PORT
                        Target port/range (e.g., 161 or 161,162 or 160-165)
  -i INTERFACE, --interface INTERFACE
                        Specify network interface (e.g., eth0, Ethernet0)
  -eid ENGINE_ID, --engine-id ENGINE_ID
                        Specify a hex agent engine ID (e.g., 0x80000000011234567890abcdef)
  -o OUTPUT, --output OUTPUT
                        CSV prepended output filename/path
  -d {0,1,2}, --debug {0,1,2}
                        Debug level to stdout
  -to TIMEOUT, --timeout TIMEOUT
                        Timeout seconds
  -rt RETRIES, --retries RETRIES
                        Retries count
  -dl DELAY, --delay DELAY
                        Seconds delay between each request
  -or OID_READ, --oid-read OID_READ
                        OID the Login module will read (default is sysDescr.0)
  -tk TASKS, --tasks TASKS
                        Number of concurrent tasks
```

## Installation

To install the tool, install/upgrade these various packages:

```cmd
python -m pip install -r 'requirements.txt'
```

## Usage

Please note that if you are only using the Post-Exploitation features, we will still check to see if your authentication is valid prior. See the module usages below:

### All

This selection will:

1. Spray v1/2c community strings
2. Spray v3 usernames (NoAuthNoPriv)
3. Spray v3 usernames and authentication passwords/algorithms (AuthNoPriv)
4. Spray v3 usernames, authentication passwords/algorithms, and privacy passwords/algorithms (AuthPriv)
5. BulkWalk any successfully accessed SNMP agents

```cmd
python SNMPede.py --all -t 'targets.txt' -c 'Dictionaries/Community_Strings.txt' -u 'Dictionaries/Usernames.txt' -p 'Dictionaries/Passwords.txt'
```

### Spray: Community Strings

```cmd
python SNMPede.py -t 'targets.txt' -c 'Dictionaries/Community_Strings.txt'
```

### Spray: Passwords

This selection will:

1. Spray usernames (NoAuthNoPriv)
2. Spray usernames and authentication passwords/algorithms (AuthNoPriv)
3. Spray usernames, authentication passwords/algorithms, and privacy passwords/algorithms (AuthPriv)

```cmd
python SNMPede.py -t 'targets.txt' -u 'Dictionaries/Usernames.txt' -p 'Dictionaries/Passwords.txt'
```

## Existing Research

Throughout history, many amazing SNMP tools have been created, but were often:

- Too specific in their hacking scope
- Were meant for system administration purposes only
- Misled users on how SNMP versioning and authentication works
- Were operating system specific or language-restricting

That said, we appreciate all the help these tools have introduced to the InfoSec community in teaching IT administrators better SNMP security!

Some of the many well known tools in the past include:

- [Net-SNMP](http://www.net-snmp.org/)
- [onesixtyone](https://github.com/trailofbits/onesixtyone)
- [SNscan](https://www.softpedia.com/get/Network-Tools/Network-IP-Scanner/SNScan.shtml)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [Nmap snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html)
- [Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/snmp/snmp_login.md)
- [snmpwn](https://github.com/hatlord/snmpwn)
- [Snmpcheck](https://www.nothink.org/codes/snmpcheck/index.php)
- [braa](https://github.com/mteg/braa)
- [Patator](https://github.com/lanjelot/patator)

