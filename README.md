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
usage: SNMPede.py [-h] [--spray] [--bulkwalk] [--all] [-c COMMUNITY] [-u USERNAME] [-p PASSWORD] [-ap {ANY,HMACMD5,HMACSHA,HMAC128SHA224,HMAC192SHA256,HMAC256SHA384,HMAC384SHA512}] [-pp {ANY,DES,AESCFB128,AESCFB192,AESCFB256}] [-t TARGET]
                  [-pt PORT] [-i INTERFACE] [-eid ENGINE_ID] [-o OUTPUT] [-d {0,1,2}] [-to TIMEOUT] [-rt RETRIES] [-dl DELAY] [-or OID_READ] [-tk TASKS]

A modern and intelligent approach to SNMP hacking

optional arguments:
  -h, --help            show this help message and exit

Modules:
  --spray               Spray any provided community strings, credentials (user/pass), and combos
  --bulkwalk            Collect as much information as possible
  --all                 CAUTION: Use all above modules

Spray Arguments:
  -c COMMUNITY, --community COMMUNITY
                        Singular community string or file containing line-delimited strings
  -u USERNAME, --username USERNAME
                        Singular username or file containing line-delimited usernames
  -p PASSWORD, --password PASSWORD
                        Singular password or file containing line-delimited passwords
  -ap {ANY,HMACMD5,HMACSHA,HMAC128SHA224,HMAC192SHA256,HMAC256SHA384,HMAC384SHA512}, --auth-proto {ANY,HMACMD5,HMACSHA,HMAC128SHA224,HMAC192SHA256,HMAC256SHA384,HMAC384SHA512}
                        Singular authentication protocol or try any of them
  -pp {ANY,DES,AESCFB128,AESCFB192,AESCFB256}, --priv-proto {ANY,DES,AESCFB128,AESCFB192,AESCFB256}
                        Singular privacy protocol or try any of them

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
                        OID the Spray module will read (default is sysDescr.0)
  -tk TASKS, --tasks TASKS
                        Number of concurrent tasks
```

## Installation

To install the tool, install/upgrade these various packages:

```cmd
python -m pip install -r requirements.txt --upgrade
```

## Usage

The Spray module is a requirement to take advantage of the BulkWalk and other future post-exploitation modules. See the module usages below:

### All

This submodule will do the following:

1. Spray v1/2c community strings
2. Spray/discover v3 usernames (NoAuthNoPriv)
3. Spray discovered v3 usernames and authentication passwords/algorithms (AuthNoPriv)
4. Spray discovered v3 usernames, discovered authentication passwords/algorithms, and privacy passwords/algorithms (AutPriv)
5. BulkWalk any successfully accessed SNMP agents

```cmd
python SNMPede.py --all -t targets.txt -c Dictionaries/Community_Strings.txt -u Dictionaries/Usernames.txt -p Dictionaries/Passwords.txt
```

### Spray: Community Strings

```cmd
python SNMPede.py --spray -t targets.txt -c Dictionaries/Community_Strings.txt
```

### Spray: Passwords

This submodule will do the following:

1. Spray/discover usernames (NoAuthNoPriv)
2. Spray discovered usernames and authentication passwords/algorithms (AuthNoPriv)
3. Spray discovered usernames, discovered authentication passwords/algorithms, and privacy passwords/algorithms (AuthPriv)

```cmd
python SNMPede.py --spray -t targets.txt -u Dictionaries/Usernames.txt -p Dictionaries/Passwords.txt
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
