from pysnmp import debug
import logging
import argparse
import argcomplete
from csv import DictWriter
from os.path import exists
from sys import platform
import asyncio
from _modules.bulkwalk import *
from _modules import config
from _modules.get_multi_v12c import *
from _modules.get_multi_v3 import *
from _modules.get_single import *
from _modules.scan_port import *
from _modules.write import *
from _modules.helpers import *
import psutil
from _modules.classes import Target


def write_fieldnames(filepath, fieldnames):
    if not exists(filepath):
        with open(filepath, 'w') as file:
            file.write(fieldnames)


def append_csv(filepath, fieldnames, data):
    with open(filepath, 'a', encoding='utf-8', newline='') as csvfile:
        writer = DictWriter(csvfile, fieldnames=fieldnames)
        for d in data:
            writer.writerow(d)


# MARK: Main
async def main():
    parser = argparse.ArgumentParser(description='A modern and intelligent approach to SNMP hacking')

    module_group = parser.add_argument_group('Modules')
    #module_group.add_argument('--scan', action='store_true', help='Scan for SNMP services')
    module_group.add_argument('-c', '--community', type=str, help='Login with a provided community string or line-delimited file')
    module_group.add_argument('-u', '--username', type=str, help='Login with a username or line-delimited file')
    module_group.add_argument('-p', '--password', type=str, help='Login with a password or line-delimited file') # Is used for auth and priv passwords/keys
    module_group.add_argument('--bulkwalk', action='store_true', help='Collect as much information as possible')
    #module_group.add_argument('--write', action='store_true', help='Check if write access is possible')
    module_group.add_argument('--all', action='store_true', help='CAUTION: Use all above modules and default login dictionaries')

    io_group = parser.add_argument_group('I/O Arguments')
    io_group.add_argument('-t', '--target', type=str, help='Singular hostname or IPv4/IPv6 address or file containing line-delimited targets')
    io_group.add_argument('-pt', '--port', default=161, help='Target port/range (e.g., 161 or 161,162 or 160-165)')
    io_group.add_argument('-i', '--interface', type=str, help='Specify network interface (e.g., eth0, Ethernet0)')
    io_group.add_argument('-eid', '--engine-id', type=str, help='Specify a hex agent engine ID (e.g., 0x80000000011234567890abcdef)')
    io_group.add_argument('-o', '--output', type=str, default='SNMPede_', help='CSV prepended output filename/path')
    io_group.add_argument('-l', '--log', type=str, default='SNMPede_Log.txt', help='Debug level 2 text output file')
    io_group.add_argument('-d', '--debug', type=int, default=0, choices=[0, 1, 2], help='Debug level to stdout')
    io_group.add_argument('-to', '--timeout', type=float, default=0.4, help='Timeout seconds')
    io_group.add_argument('-rt', '--retries', type=int, default=0, help='Retries count')
    io_group.add_argument('-dl', '--delay', type=float, default=0.3, help='Seconds delay between each request')
    io_group.add_argument('-or', '--oid-read', type=str, default='1.3.6.1.2.1.1.1.0', help='OID the Login module will read (default is sysDescr.0)')
    io_group.add_argument('-tk', '--tasks', type=int, default=10, help='Number of concurrent tasks')
    #io_group.add_argument('-cb', '--combo', help='File containing line-delimited combos (host,port,username,password/string)')
    #io_group.add_argument('-ow', '--oid-write', type=str, default='', help='')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    Target_instances = []
    semaphore = asyncio.Semaphore(args.tasks)
    await asyncio.sleep(0.2)

    ascii_art = """
.▄▄ ·  ▐ ▄ • ▌ ▄ ·.  ▄▄▄·▄▄▄ .·▄▄▄▄  ▄▄▄ .
▐█ ▀. •█▌▐█·██ ▐███▪▐█ ▄█▀▄.▀·██▪ ██ ▀▄.▀·
▄▀▀▀█▄▐█▐▐▌▐█ ▌▐▌▐█· ██▀·▐▀▀▪▄▐█· ▐█▌▐▀▀▪▄
▐█▄▪▐███▐█▌██ ██▌▐█▌▐█▪·•▐█▄▄▌██. ██ ▐█▄▄▌
 ▀▀▀▀ ▀▀ █▪▀▀  █▪▀▀▀.▀    ▀▀▀ ▀▀▀▀▀•  ▀▀▀ 
    """
    print(ascii_art)

    # Update inter-module global variables in config.py with the provided args
    config.ARGTIMEOUT, config.ARGRETRIES, config.ARGDELAY, config.ARGDEBUG, config.OID_READ = args.timeout, args.retries, args.delay, args.debug, args.oid_read

    # Tier 2 debugging
    if config.ARGDEBUG >= 2:
        logging.basicConfig(
            filename=args.log,
            filemode='a',
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Create a logger for PySNMP
        logger = logging.getLogger('pysnmp')
        logger.setLevel(logging.DEBUG)
        
        # Enable PySNMP debugging
        debug.set_logger(debug.Debug('all'))

    # MARK: Exception Checks
    if not args.target:
        print("[e] No target was provided. Please add one.")
        parser.print_help()
        quit()
    else:
        # Convert the singular or multiple targets to a list
        targets = await convert_to_list(args.target)
        if config.ARGDEBUG >= 1: print("[d] Detected the following:\n[d] " + str(len(targets)) + ' target(s)')
        tasks = []
        for target in targets: # Returns (FQDN, IP, Version)
            tasks.append(asyncio.create_task(resolve_target(target)))

    if not (args.community or args.username or args.password or args.bulkwalk or args.all): #args.scan
        print("[e] No module was selected. Please pick one:")
        parser.print_help()
        quit()

    # Tell async task to raise an exception
    for task in tasks:
        task.add_done_callback(handle_task_result)

    # Wait for name resolution to finish before continuing
    try:
        resolved_targets = await asyncio.gather(*tasks)
    except Exception as e:
        print(f"[e] A resolution error occurred: {e}")
        quit()

    # Check interface existance and compatibility
    if args.interface:
        # Get network interface addresses
        interfaces = psutil.net_if_addrs()

        # Check if the NIC name exists in the addresses
        for interface_name, addresses in interfaces.items():
            if interface_name.lower() == (args.interface).lower():
                for address in addresses: # Single interface could have both an IPv4 and IPv6 address, or sadly multiple of each
                    if any('v4' in tup for tup in resolved_targets) and address.family == AF_INET:
                        config.INTERFACE_ADDR4 = address.address
                    elif any('v6' in tup for tup in resolved_targets) and address.family == AF_INET6:
                        config.INTERFACE_ADDR6 = address.address
        if not config.INTERFACE_ADDR4 and not config.INTERFACE_ADDR6:
            print("[e] Provided interface not found. Interfaces found:")
            for interface_name, addresses in interfaces.items():
                print("    '" + interface_name + "'")
            quit()
        elif any('v4' in tup for tup in resolved_targets) and not config.INTERFACE_ADDR4:
            print("[e] An IPv4 target was provided, but the provided interface does not support IPv4.")
            quit()
        elif any('v6' in tup for tup in resolved_targets) and not config.INTERFACE_ADDR6:
            print("[e] An IPv6 target was provided, but the provided interface does not support IPv6.")
            quit()
        elif config.ARGDEBUG >= 1:
            print(f"[d] NIC: {args.interface}")
            print(f"[d] IPv4 local address: {config.INTERFACE_ADDR4}")
            print(f"[d] IPv6 local address: {config.INTERFACE_ADDR6}")
    

    if args.all and not (args.community or args.username or args.password):
        print("[e] Although the All module was specified, neither a community, username, or password was provided.")
        parser.print_help()
        quit()

    # Convert the singular or multiple ports to a list
    ports = await parse_ports(args.port)
    if config.ARGDEBUG >= 1: print("[d] " + str(len(ports)) + ' port(s)')

    if args.community:
        # Convert the singular or multiple community strings to a list
        community_strings = await convert_to_list(args.community)
        if config.ARGDEBUG >= 1: print("[d] " + str(len(community_strings)) + ' community string(s)')

    if args.username:
        # Convert the singular or multiple values to a list
        usernames = await convert_to_list(args.username)
        if config.ARGDEBUG >= 1: print("[d] " + str(len(usernames)) + ' username(s)')

    if args.password:
        if not args.username:
            print("[e] Password(s) detected, but no usernames detected. Please adjust.")
            quit()
        
        # Convert the singular or multiple passwords to a list
        passwords = await convert_to_list(args.password)
        if config.ARGDEBUG >= 1: print("[d] " + str(len(passwords)) + ' password(s)')

        # SNMP v3 does not allow less than 8 character passwords. Error if we have any
        if any(len(password) < 8 for password in passwords):
            print("[e] SNMP v3 does not allow passwords less than 8 characters. Please adjust.")
            quit()
    
    # Agent engine ID requires `0x`, make sure it does:
    if args.engine_id and not (args.engine_id).startswith('0x'):
        config.ENGINE_ID = '0x' + args.engine_id
    else:
        config.ENGINE_ID = args.engine_id

    # Map custom auth protocol to Name/Class
    auth_protocols = [
        {'Name': 'HMACMD5', 'Class': usmHMACMD5AuthProtocol},
        {'Name': 'HMACSHA', 'Class': usmHMACSHAAuthProtocol},
        {'Name': 'HMAC128SHA224', 'Class': usmHMAC128SHA224AuthProtocol},
        {'Name': 'HMAC192SHA256', 'Class': usmHMAC192SHA256AuthProtocol},
        {'Name': 'HMAC256SHA384', 'Class': usmHMAC256SHA384AuthProtocol},
        {'Name': 'HMAC384SHA512', 'Class': usmHMAC384SHA512AuthProtocol}
    ]

    # Map custom priv protocol to Name/Class
    priv_protocols = [
        {'Name': 'DES', 'Class': usmDESPrivProtocol},
        {'Name': 'AESCFB128', 'Class': usmAesCfb128Protocol},
        {'Name': 'AESCFB192', 'Class': usmAesCfb192Protocol},
        {'Name': 'AESCFB256', 'Class': usmAesCfb256Protocol}
    ]

    # MARK: Scan
    # if args.scan or args.all:
    #     if config.ARGDEBUG >=1: print() # For pretty stdout
    #     print("[i] Performing SNMP port scanning...")
    #     tasks = []
    #     for target in resolved_targets:
    #         for port in ports:
    #             print(f'[-] Scanning {target[0]}:{port}')
    #             tasks.append(scan_port(target, port))
        
    #     outputfile = args.output + 'Scan.csv'
    #     if not exists(outputfile):
    #         write_fieldnames(outputfile, 'Host,Protocol,Port,Service,Status\n')

    #    # Tell async task to raise an exception
    #    for task in tasks:
    #        task.add_done_callback(handle_task_result)
    #
    #     # Wait for port scanning to finish
    #     try:
    #         task_results = await asyncio.gather(*tasks)
    #     except Exception as e:
    #         print(f"[e] A scan error occurred: {e}")
    #         quit()

        # print("[-] Writing results...")
        # imported_instances = False
        # for r, instances in task_results:
        #     append_csv(outputfile, ['Host', 'Protocol', 'Port', 'Service', 'Status'], r)
        #     if imported_instances is False:
        #         for instance in instances:
        #             Target_instances.append(instance)
        #         imported_instances = True

    #     if len(Target_instances) == 0:
    #         print(f"[i] No open port(s) found{quit_text}.\n")
    #         quit()
    #     else:
    #         print() # For pretty stdout


    # If we are not spraying, but instead just checking authentication, let's clarify that:
    if config.WASFILEIMPORTED:
        intention = 'Spray'
    else:
        intention = 'Check'


    # MARK: Comm_Strings
    if args.community:
        if config.ARGDEBUG >=1: print() # For pretty stdout #  and not args.scan
        print(f"[i] {intention}ing SNMP versions 1/2c community string(s)...")
        tasks = []
        task_results = []
        
        # Perform v1 community string spraying/checking
        if len(Target_instances) > 0:
            if config.ARGDEBUG >= 1: print(f"[d] Using the existing ({len(Target_instances)}) instances:")
            for id, instance in enumerate(Target_instances):
                tasks.append(asyncio.create_task(snmp_v12c_get_multi(semaphore, id, (instance.FQDN, instance.IP, instance.IPVersion), instance.port, 'v1', community_strings, instance=instance)))
        else:
            id = 0
            for target in resolved_targets:
                for port in ports:
                    tasks.append(asyncio.create_task(snmp_v12c_get_multi(semaphore, id, target, port, 'v1', community_strings)))
                    id = id + 1
        
        # Tell async task to raise an exception
        for task in tasks:
            task.add_done_callback(handle_task_result)

        # Wait for community string v1 spraying/checking to finish before beginning v2c
        try:
            task_results.extend(await asyncio.gather(*tasks))
        except Exception as e:
            print(f"[e] A v1 community string {intention.lower()}ing error occurred: {e}")
            quit()

        # Perform v2c community string spraying/checking
        task_results = []
        if len(Target_instances) > 0:
            for id, instance in enumerate(Target_instances):
                tasks.append(asyncio.create_task(snmp_v12c_get_multi(semaphore, id, (instance.FQDN, instance.IP, instance.IPVersion), instance.port, 'v2c', community_strings, instance=instance)))
        else:
            id = 0
            for target in resolved_targets:
                for port in ports:
                    tasks.append(asyncio.create_task(snmp_v12c_get_multi(semaphore, id, target, port, 'v2c', community_strings)))
                    id = id + 1
        
        # Tell async task to raise an exception
        for task in tasks:
            task.add_done_callback(handle_task_result)

        # Wait for community string v2c spraying/checking to finish
        try:
            task_results.extend(await asyncio.gather(*tasks))
        except Exception as e:
            print(f"[e] A v2c community string {intention.lower()}ing error occurred: {e}")
            quit()

        outputfile = args.output + f"v12c_{intention}_Community_Strings.csv"
        if not exists(outputfile):
            write_fieldnames(outputfile, 'Host,Port,Version,CommunityString,OID,Value,Status\n')

        print("[-] Writing results...")
        for r, instances in task_results:
            append_csv(outputfile, ['Host', 'Port', 'Version', 'CommunityString', 'OID', 'Value', 'Status'], r)
            for instance in instances:
                Target_instances.append(instance)
        
        if len(Target_instances) == 0:
            print(f"[i] No community string(s) found.\n")
            quit()
        else:
            print() # For pretty stdout

    
    # MARK: UserEnum
    if args.username:
        if config.ARGDEBUG >=1 and not args.community: print() # For pretty stdout # (args.scan or args.community)
        print(f"[i] {intention}ing SNMP v3 username(s) with NoAuthNoPriv...")
        tasks = []
        task_results = []
        
        instances = get_instances_with_attribute(Target_instances, 'Access', False)
        if instances:
            if config.ARGDEBUG >= 1: print(f"[d] Using the relevant ({len(instances)}) instances:")
            for id, instance in enumerate(Target_instances):
                tasks.append(asyncio.create_task(snmp_v3_get_multi(semaphore, id, (instance.FQDN, instance.IP, instance.IPVersion), instance.Port, usernames, instance=instance)))
        else:
            id = 0
            for target in resolved_targets:
                for port in ports:
                    tasks.append(asyncio.create_task(snmp_v3_get_multi(semaphore, id, target, port, usernames)))
                    id = id + 1
        
        outputfile = args.output + f"v3_{intention}_Credentials.csv"
        if not exists(outputfile):
            write_fieldnames(outputfile, 'Host,Port,Version,Username,AuthPassword,AuthProtocol,PrivPassword,PrivProtocol,OID,Value,Status\n')

        # Tell async task to raise an exception
        for task in tasks:
            task.add_done_callback(handle_task_result)

        # Wait for username spraying/checking to finish
        try:
            task_results.extend(await asyncio.gather(*tasks))
        except Exception as e:
            print(f"[e] A username {intention.lower()}ing error occurred: {e}")
            quit()

        print("[-] Writing results...")
        imported_instances = False
        for r, instances in task_results:
            append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
            if imported_instances is False:
                for instance in instances:
                    Target_instances.append(instance)
                imported_instances = True
        
        if len(Target_instances) == 0 or len(get_instances_with_attribute(Target_instances, 'Username')) == 0:
            print(f"[i] No username(s) found.\n")
            quit()
        else:
            print() # For pretty stdout


    # MARK: AuthPwd
    if args.password:
        tasks = []
        task_results = []
        
        # Filter for any unfinished targets
        instances = get_instances_with_attribute(Target_instances, 'Access', False)
        # Filter for those with Username not None
        instances = get_instances_with_attribute(instances, 'Username')
        if instances:
            print(f"[i] {intention}ing SNMP v3 password(s) with AuthNoPriv...")
            if config.ARGDEBUG >= 1: print(f"[d] Using the relevant ({len(instances)}) instances:")
            for id, instance in enumerate(instances):
                tasks.append(asyncio.create_task(snmp_v3_get_multi(semaphore, id, (instance.FQDN, instance.IP, instance.IPVersion), instance.Port, instance.Username, authpasswords=passwords, authprotocols=auth_protocols, instance=instance)))

            # Tell async task to raise an exception
            for task in tasks:
                task.add_done_callback(handle_task_result)

            # Wait for auth spraying/checking to finish
            try:
                task_results.extend(await asyncio.gather(*tasks))
            except Exception as e:
                print(f"[e] An AuthNoPriv {intention.lower()}ing error occurred: {e}")
                quit()

            print("[-] Writing results...")
            for r in task_results:
                append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
            
            if len(Target_instances) == 0 or len(get_instances_with_attribute(Target_instances, 'AuthPwd')) == 0:
                print(f"[i] No AuthNoPriv password(s) found.\n")
                quit()
            else:
                print() # For pretty stdout
        else:
            print(f"[i] Skipping {intention.lower()}ing AuthNoPriv as its unnecessary...\n")

        
        # MARK: PrivPwd
        # Doing async like this so that we don't DDOS a specific SNMP agent
        # Filter for any unfinished targets
        instances = get_instances_with_attribute(Target_instances, 'Access', False)
        # Filter for those with AuthPwd not None
        instances = get_instances_with_attribute(instances, 'AuthPwd')
        if instances:
            print(f"[i] {intention}ing SNMP v3 password(s) with AuthPriv...")
            tasks = []
            task_results = []
            if config.ARGDEBUG >= 1: print(f"[d] Using the relevant ({len(instances)}) instances:")
            for id, instance in enumerate(instances):
                tasks.append(asyncio.create_task(snmp_v3_get_multi(semaphore, id, (instance.FQDN, instance.IP, instance.IPVersion), instance.Port, instance.Username, authpasswords=instance.AuthPwd, authprotocols=instance.AuthProto, privpasswords=passwords, privprotocols=priv_protocols, instance=instance)))

            # Tell async task to raise an exception
            for task in tasks:
                task.add_done_callback(handle_task_result)

            # Wait for AuthPriv spraying/checking to finish
            try:
                task_results.extend(await asyncio.gather(*tasks))
            except Exception as e:
                print(f"[e] An AuthPriv {intention.lower()}ing error occurred: {e}")
                quit()

            print("[-] Writing results...")
            for r in task_results:
                append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
            
            if len(Target_instances) == 0 or len(get_instances_with_attribute(Target_instances, 'PrivPwd')) == 0:
                print(f"[i] No AuthPriv password(s) found.\n")
            else:
                print() # For pretty stdout
        else:
            print(f"[i] Skipping {intention.lower()}ing AuthPriv as its unnecessary...\n")

    # We need to cleanse no Access instances so that our post-access
    # activities can be efficient
    for instance in Target_instances:
        if instance.Access == False:
            Target_instances.remove(instance)
            del instance


    # MARK: BulkWalk
    if args.bulkwalk or args.all:
        if not Target_instances:
            print("[i] No successful access was achieved. Skipping BulkWalk module.")
        else:
            # Doing async like this so that we don't DDOS a specific SNMP agent
            instances = get_instances_with_attribute(Target_instances, 'CommunityString')
            tasks = []
            task_results = []
            print("[i] BulkWalking v1/2c information...")
            if instances:
                if config.ARGDEBUG >= 1: print(f"[d] Using the relevant ({len(instances)}) v1/2c instances:")
                for id, instance in enumerate(instances):
                    if config.ARGDEBUG >= 1: print(instance)
                    tasks.append(asyncio.create_task(snmp_v12c_bulkwalk(semaphore, id, instance)))
            
                outputfile = args.output + 'v12c_BulkWalk.csv'
                if not exists(outputfile):
                    write_fieldnames(outputfile, 'Host,Port,Version,CommunityString,OID,Value,Status\n')

                # Tell async task to raise an exception
                for task in tasks:
                    task.add_done_callback(handle_task_result)
                
                # Wait for BulkWalk to finish
                try:
                    task_results.extend(await asyncio.gather(*tasks))
                except Exception as e:
                    print(f"[e] A v1/2c BulkWalk error occurred: {e}")
                    quit()

                print("[-] Writing results...\n")
                for r in task_results:
                    if r:
                        append_csv(outputfile, ['Host', 'Port', 'Version', 'CommunityString', 'OID', 'Value', 'Status'], r)

            instances = get_instances_with_attribute(Target_instances, 'Username')
            if instances:
                tasks = []
                task_results = []
                print("[i] BulkWalking v3 information...")
                if config.ARGDEBUG >= 1: print(f"[d] Using the relevant ({len(instances)}) v3 instances:")
                for id, instance in enumerate(instances):
                    if config.ARGDEBUG >= 1: print(instance)
                    tasks.append(asyncio.create_task(snmp_v3_bulkwalk(semaphore, id, instance)))
            
                outputfile = args.output + 'v3_BulkWalk.csv'
                if not exists(outputfile):
                    write_fieldnames(outputfile, 'Host,Port,Username,AuthPassword,AuthProtocol,PrivPassword,PrivProtocol,OID,Value,Status\n')

                # Tell async task to raise an exception
                for task in tasks:
                    task.add_done_callback(handle_task_result)

                # Wait for BulkWalk to finish
                try:
                    task_results.extend(await asyncio.gather(*tasks))
                except Exception as e:
                    print(f"[e] A v3 BulkWalk error occurred: {e}")
                    quit()

                print("[-] Writing results...\n")
                for r in task_results:
                    append_csv(outputfile, ['Host', 'Port', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)


if __name__ == '__main__':
    try:
        if platform == 'win32':
            # https://stackoverflow.com/questions/63860576/asyncio-event-loop-is-closed-when-using-asyncio-run
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print('[e] Program termination requested by user')
