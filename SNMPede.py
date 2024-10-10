from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp import debug
import argparse
import argcomplete
from csv import DictWriter
from os.path import exists
from pysnmp.proto import rfc1902
#import socket
import asyncio
from _modules.helpers import *
import psutil
import traceback

# MARK: Target Class
class Target:

    instances = []

    def __init__(self, FQDN, IP, IPVersion, Port, SNMPVersion=None, CommunityString=None, Username=None, AuthPwd=None, AuthProto=None, PrivPwd=None, PrivProto=None, Access=False):
        self.FQDN = FQDN # Some provided targets may not have a DNS FQDN. If they don't, this will be the IP address also.
        self.IP = IP
        self.IPVersion = IPVersion
        self.SNMPVersion = SNMPVersion
        self.CommunityString = CommunityString
        self.Username = Username
        self.AuthPwd = AuthPwd
        self.AuthProto = AuthProto # ['Name': 'NicknameAlgo', 'Class': USMAlgoClass]
        self.PrivPwd = PrivPwd
        self.PrivProto = PrivProto # ['Name': 'NicknameAlgo', 'Class': USMAlgoClass]
        self.Port = Port
         # We'll use this below attribute to keep track of if an entry needs more spraying
         # Like don't spray usernames on this instance if a community string was successfully found
         # And vice versa.
        self.Access = Access
        # Add the new instance to the instances list
        Target.instances.append(self)

    def __str__(self):
        return f"[d]   {self.FQDN}:{self.Port}/{self.SNMPVersion} via {self.CommunityString}/{self.Username}/{self.AuthPwd}/{self.AuthProto}/{self.PrivPwd}/{self.PrivProto}, Access: {self.Access}"

    def __del__(self):
        # Remove the instance from the instances list when it is destroyed
        Target.instances.remove(self)

    @property
    def IPVersion(self):
        return self._IPVersion

    @IPVersion.setter
    def IPVersion(self, value):
        if value not in ["v4", "v6", 'both']:
            # If presented the option between v4 or v6, we mark it based upon the first resolved record's type
            raise ValueError("IPVersion must be 'v4' or 'v6'.")
        self._IPVersion = value

    @property
    def SNMPVersion(self):
        return self._SNMPVersion
    
    @SNMPVersion.setter
    def SNMPVersion(self, value):
        if value not in ["v1", "v2c", "v3"]:
            raise ValueError("SNMPVersion must be 'v1', 'v2c, or 'v3'.")
        self._SNMPVersion = value

    @classmethod
    def get_instances(cls):
        # Class method to get the list of all instances
        return cls.instances


def write_fieldnames(filepath, fieldnames):
    if not exists(filepath):
        with open(filepath, 'w') as file:
            file.write(fieldnames)


# MARK: scan_port
# async def scan_port(target, port, timeout):
#     try:
#         # Create a UDP socket for IPv4 or IPv6
#         if target[2] == 'v4':
#             family = socket.AF_INET
#         else:
#             family = socket.AF_INET6
#         sock = socket.socket(family, socket.SOCK_DGRAM)
#         sock.settimeout(timeout)

#         # Send a dummy SNMP request (v1 via public community string like Nmap)
#         data = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\x3b\x1d\x4b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x00\x05\x00'
#         if interface_addr4:
#             sock.bind((interface_addr4, port))
#         elif interface_addr6:
#             sock.bind((interface_addr6, port))
#         sock.sendto(data, (target[0], port))

#         # Receive response
#         response, _ = sock.recvfrom(1024)
#         if response:
#             print("Found something!")
#             Target(target[0], target[1], target[2], port)
#             return {'Host': target[0], 'Protocol': 'UDP', 'Port': port, 'Service': 'SNMP', 'Status': 'Open'}
#     except socket.timeout:
#         return {'Host': target[0], 'Protocol': 'UDP', 'Port': port, 'Service': 'SNMP', 'Status': 'Error: Timeout'}
#     except Exception as e:
#         print(f"[e] Error scanning {target}:{port}: {e}")
#         return {'Host': target[0], 'Protocol': 'UDP', 'Port': port, 'Service': 'SNMP', 'Status': e}
#     finally:
#         sock.close()


def append_csv(filepath, fieldnames, data):
    with open(filepath, 'a', encoding='utf-8', newline='') as csvfile:
        writer = DictWriter(csvfile, fieldnames=fieldnames)
        for d in data:
            writer.writerow(d)


# MARK: v1/2c Login
async def snmp_v12c_get(target, port, version, timeout, retries, delay, community_strings, instance=None):
    # CAUTION:
    # Target may be {FQDN, IP, IPVersion} sometimes pending the availability of an instance, hence the below standardization
    if instance:
        target = (instance.FQDN, instance.IP, instance.IPVersion)
    
    success = False

    results = []
    if engine_id:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=engine_id))
    else:
        snmpEngine = SnmpEngine()
    
    await asyncio.sleep(delay)

    mpModel = 0 if version == 'v1' else 1  # SNMPv1 is mpModel 0, SNMPv2c is mpModel 1. Note that 2c often is backwards compatible
    for community_string in community_strings:
        if argdebug >= 1: print(f"[d] '{community_string}' -> {target[0]}:{port}/{version}")

        if target[2] == 'v4' or instance.IPVersion == 'v4':
            if instance:
                transport_target = await UdpTransportTarget.create((instance.FQDN, port), timeout, retries)
            else:
                transport_target = await UdpTransportTarget.create((target[0], port), timeout, retries)
        else:
            if instance:
                transport_target = await Udp6TransportTarget.create((instance.FQDN, port), timeout, retries)
            else:
                transport_target = await Udp6TransportTarget.create((target[0], port), timeout, retries)
        
        # Bind to NIC IP address
        if interface_addr4:
            transport_target.transportDomain = (interface_addr4, 0)
        elif interface_addr6:
            transport_target.transportDomain = (interface_addr6, 0)

        await asyncio.sleep(delay)

        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            snmpEngine,
            CommunityData(community_string, mpModel=mpModel),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(oid_read))
        )

        if errorIndication:
            if argdebug >= 1: print(f"[d] Error: {errorIndication}")
            results.append({'Host': target[0], 'Port': port, 'Version': version, 'CommunityString': community_string, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorIndication}"})
        elif errorStatus:
            if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
            results.append({'Host': target[0], 'Port': port, 'Version': version, 'CommunityString': community_string, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
        else:
            print(f"[!] Found '{community_string}' at {target[0]}:{port}/{version}")
            if not instance or success is True:
                Target(target[0], target[1], target[2], port, SNMPVersion=version, CommunityString=community_string, Access=True)
                success = True
            else:
                instance.SNMPVersion = version
                instance.CommunityString = community_string
                instance.Access = True
                success = True
            
            for varBind in varBinds:
                results.append({'Host': target[0], 'Port': port, 'Version': version, 'CommunityString': community_string, 'OID': oid_read, 'Value': str(varBind), 'Status': "Success"})
    
    if success is False:
        del instance

    # [{Host, Port, Version, Community, OID, Value, Status}]
    return results


# Function to get instances with a specific attribute value
def get_instances_with_attribute(instances, attribute_name, attribute_value=None):
    matching_instances = []
    for instance in instances:
        if attribute_value is not None:
            if hasattr(instance, attribute_name) and getattr(instance, attribute_name) == attribute_value:
                matching_instances.append(instance)
        else:
            if hasattr(instance, attribute_name) and getattr(instance, attribute_name) is not None:
                matching_instances.append(instance)
    return matching_instances

# MARK: v3 Login
async def snmp_v3_get(target, port, timeout, retries, delay, usernames, authpasswords=None, authprotocols=None, privpasswords=None, privprotocols=None, instance=None):
    # CAUTION:
    # Usernames/auth/priv-passwords/auth/priv-protocols parameters above are used interchangeably in singular and multiple forms for ease of programming
    # Also, target may be {FQDN, IP, IPVersion} sometimes pending the relevance of an instance, hence the below standardization
    if instance and not authpasswords:
        target = (instance.FQDN, instance.IP, instance.IPVersion)
    
    # For username spraying: defined as finding a username in any capacity
    success = False

    results = []
    if engine_id:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=engine_id))
    else:
        snmpEngine = SnmpEngine()
    
    if target[2] == 'v4' or instance.IPVersion == 'v4':
        if instance:
            transport_target = await UdpTransportTarget.create((instance.FQDN, port), timeout, retries)
        else:
            transport_target = await UdpTransportTarget.create((target[0], port), timeout, retries)
    else:
        if instance:
            transport_target = await Udp6TransportTarget.create((instance.FQDN, port), timeout, retries)
        else:
            transport_target = await Udp6TransportTarget.create((target[0], port), timeout, retries)
    
    # Bind to NIC IP address
    if interface_addr4:
        transport_target.transportDomain = (interface_addr4, 0)
    elif interface_addr6:
        transport_target.transportDomain = (interface_addr6, 0)

    await asyncio.sleep(delay)

    if type(usernames) == list:
        for username in usernames:
            if argdebug >= 1: print(f"[d] '{username}' -> {target[0]}:{port}")
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                snmpEngine,
                UsmUserData(userName=username),
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(oid_read)) 
            )
            if errorIndication:
                if "Wrong SNMP PDU digest" in str(errorIndication) or "Unsupported SNMP security level" in str(errorIndication):
                    print(f"[!] Found '{username}' at {target[0]}:{port}")

                    if not instance or success is True:
                        Target(target[0], target[1], target[2], port, SNMPVersion='v3', Username=username)
                        success = True
                    else:
                        instance.SNMPVersion = 'v3'
                        instance.Username = username
                        # Because we are not setting Target.Access = True and it is still false with a Username,
                        # we tell future processses that NoAuthNoPriv was not sufficient, more is needed.
                        success = True

                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"User Discovered: {errorIndication}"})
                else:
                    if argdebug >= 1: print(f"[d] Error: {errorIndication}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorIndication}"})
            elif errorStatus:
                if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
            else:
                print(f"[!] Found '{username}' at {target[0]}:{port}")
                if not instance or success is True:
                    Target(target[0], target[1], target[2], port, SNMPVersion='v3', Username=username, Access=True)
                    success = True
                else:
                    instance.SNMPVersion = 'v3'
                    instance.Username = username
                    instance.Access = True
                    success = True

                for varBind in varBinds:
                    if argdebug >= 1: print(f"[d] Success: {varBind}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': str(varBind), 'Status': "Success"})
    
    elif not privpasswords: # MARK: #v3-Auth
        for password in authpasswords:
            for protocol in authprotocols:
                if argdebug >= 1: print(f"[d] '{usernames}/{password}/{protocol['Name']}' -> {target}:{port}")
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    snmpEngine,
                    UsmUserData(userName=usernames, authKey=password, authProtocol=protocol['Class']),
                    transport_target,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid_read))
                )
                if errorIndication:
                    if "Wrong SNMP PDU digest" in str(errorIndication):
                        results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Wrong Pwd/Algo: {errorIndication}"})
                    elif "Unsupported SNMP security level" in str(errorIndication):
                        print(f"[!] Found '{usernames}/{password}/{protocol['Name']}' at {target}:{port}, but need Privacy")
                        results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Correct Auth, But Need Privacy: {errorIndication}"})
                        
                        instance.AuthPwd = password
                        instance.AuthProto = protocol
                        # No reason to keep auth guessing if the authpwd has been guessed
                        return results
                    else:
                        results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorIndication}"})
                elif errorStatus:
                    if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                    results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
                else:
                    print(f"[!] Found '{usernames}/{password}/{protocol['Name']}' at {target}:{port}")
                    instance.AuthPwd = password
                    instance.AuthProto = protocol
                    instance.Access = True

                    for varBind in varBinds:
                        if argdebug >= 1: print(f"[d] Success: {varBind}")
                        results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': oid_read, 'Value': str(varBind), 'Status': "Success"})
                    # No reason to keep auth guessing if the authpwd has been guessed
                    return results
    
    else: # MARK: #v3-Priv
        for password in privpasswords:
            for protocol in privprotocols:
                if argdebug >= 1: print(f"[d] '{usernames}/{authpasswords}/{authprotocols['Name']}/{password}/{protocol['Name']}' -> {target}:{port}")
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    snmpEngine,
                    UsmUserData(userName=usernames, authKey=authpasswords, authProtocol=authprotocols['Class'], privKey=password, privProtocol=protocol['Class']),
                    transport_target,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid_read))
                )

                if errorIndication:
                    results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorIndication}"})
                elif errorStatus:
                    if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                    results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': oid_read, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
                else:
                    print(f"[!] Found '{usernames}/{authpasswords}/{authprotocols['Name']}/{password}/{protocol['Name']}' at {target}:{port}")
                    instance.PrivPwd = password
                    instance.PrivProto = protocol
                    instance.Access = True

                    for varBind in varBinds:
                        if argdebug >= 1: print(f"[d] Success: {varBind}")
                        results.append({'Host': target, 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': oid_read, 'Value': str(varBind), 'Status': "Success"})
                    # No reason to keep auth guessing if the privpwd has been guessed
                    return results
    return results


# MARK: v1/2c bulkwalk
async def snmp_v12c_bulkwalk(instance, timeout, retries, delay):
    results = []
    if engine_id:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=engine_id))
    else:
        snmpEngine = SnmpEngine()
    
    if instance.IPVersion == 'v4':
        transport_target = await UdpTransportTarget.create((instance.FQDN, instance.Port), timeout, retries)
    else:
        transport_target = await Udp6TransportTarget.create((instance.FQDN, instance.Port), timeout, retries)
    
    # Bind to NIC IP address
    if interface_addr4:
        transport_target.transportDomain = (interface_addr4, 0)
    elif interface_addr6:
        transport_target.transportDomain = (interface_addr6, 0)

    await asyncio.sleep(delay)

    if instance.SNMPVersion == 'v1':
        mpModel = 0
        print("[i] Skipping a v1 instance due to lack of bulkwalk compatibility [COMING SOON!]")
        return None
    else:
        mpModel = 1
        if argdebug >= 1: print(f"[d] '{instance.CommunityString}' -> {instance.FQDN}:{instance.Port}/{instance.SNMPVersion}")

    start_varBindType = ObjectType(ObjectIdentity('1.3.6.1.2.1')) # The start of SNMP MIB
    initialOID = rfc1902.ObjectName("1.3.6.1.2.1")

    while start_varBindType:
        errorIndication, errorStatus, errorIndex, varBindTable = await bulkCmd(
            snmpEngine,
            CommunityData(instance.CommunityString, mpModel=mpModel),
            transport_target,
            ContextData(),
            0, 50,
            start_varBindType,
            lookupMib=False
        )

        if errorIndication:
            #print(errorIndication)
            results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Version': instance.SNMPVersion, 'CommunityString': instance.CommunityString, 'OID': None, 'Value': None, 'Status': f"Error: {errorIndication}"})
            break
        elif errorStatus:
            if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
            results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Version': instance.SNMPVersion, 'CommunityString': instance.CommunityString, 'OID': None, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
        else:
            #print(f"[!] Found data at '{instance.FQDN}:{instance.Port}/{instance.SNMPVersion}/{instance.Username}")
            for varBindRow in varBindTable:
                #print(f"{varBindRow[0]} {varBindRow[1]}")
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Version': instance.SNMPVersion, 'CommunityString': instance.CommunityString, 'OID': str(varBindRow[0]), 'Value': str(varBindRow[1]), 'Status': "Success"})
                
            if varBindRow[1].tagSet == EndOfMibView.tagSet or initialOID.isPrefixOf(varBindTable[-1][0]):
                break

    return results


# MARK: v3 bulkwalk
async def snmp_v3_bulkwalk(instance, timeout, retries, delay):
    results = []
    if engine_id:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=engine_id))
    else:
        snmpEngine = SnmpEngine()
    
    if instance.IPVersion == 'v4':
        transport_target = await UdpTransportTarget.create((instance.FQDN, instance.Port), timeout, retries)
    else:
        transport_target = await Udp6TransportTarget.create((instance.FQDN, instance.Port), timeout, retries)
    
    # Bind to NIC IP address
    if interface_addr4:
        transport_target.transportDomain = (interface_addr4, 0)
    elif interface_addr6:
        transport_target.transportDomain = (interface_addr6, 0)

    await asyncio.sleep(delay)

    if instance.PrivProto:
        if argdebug >= 1: print(f"[d] '{instance.Username}/{instance.AuthPwd}/{instance.AuthProto['Name']}/{instance.PrivPwd}/{instance.PrivProto['Name']}' -> {instance.FQDN}:{instance.Port}")
        usmuserdata = UsmUserData(userName=instance.Username, authKey=instance.AuthPwd, authProtocol=instance.AuthProto['Class'], privKey=instance.PrivPwd, privProtocol=instance.PrivProto['Class'])
    elif instance.AuthProto:
        if argdebug >= 1: print(f"[d] '{instance.Username}/{instance.AuthPwd}/{instance.AuthProto['Name']}' -> {instance.FQDN}:{instance.Port}")
        usmuserdata = UsmUserData(userName=instance.Username, authKey=instance.AuthPwd, authProtocol=instance.AuthProto['Class'])
    else:
        if argdebug >= 1: print(f"[d] '{instance.Username}' -> {instance.FQDN}:{instance.Port}")
        usmuserdata = UsmUserData(userName=instance.Username)

    start_varBindType = ObjectType(ObjectIdentity('1.3.6.1.2.1')) # The start of SNMP MIB
    initialOID = rfc1902.ObjectName("1.3.6.1.2.1")

    while start_varBindType:
        errorIndication, errorStatus, errorIndex, varBindTable = await bulkCmd(
            snmpEngine,
            usmuserdata,
            transport_target,
            ContextData(),
            0, 50,
            start_varBindType,
            lookupMib=False
        )

        if errorIndication:
            #print(errorIndication)
            if instance.PrivProto:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': instance.PrivPwd, 'PrivProtocol': instance.PrivProto['Name'], 'OID': None, 'Value': None, 'Status': f"Error: {errorIndication}"})
            
            elif instance.AuthProto:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': None, 'Value': None, 'Status': f"Error: {errorIndication}"})
            else:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': None, 'Value': None, 'Status': f"Error: {errorIndication}"})
            break
        elif errorStatus:
            if argdebug >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
            if instance.PrivProto:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': instance.PrivPwd, 'PrivProtocol': instance.PrivProto['Name'], 'OID': None, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
            
            elif instance.AuthProto:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': None, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
            else:
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': None, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
        else:
            #print(f"[!] Found data at '{instance.FQDN}:{instance.Port}/{instance.SNMPVersion}/{instance.Username}")
            for varBindRow in varBindTable:
                if instance.PrivProto:
                    #print(f"{varBindRow[0]} {varBindRow[1]}")
                    results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': instance.PrivPwd, 'PrivProtocol': instance.PrivProto['Name'], 'OID': str(varBindRow[0]), 'Value': str(varBindRow[1]), 'Status': "Success"})
                elif instance.AuthProto:
                    #print(f"{varBindRow[0]} {varBindRow[1]}")
                    results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': instance.AuthPwd, 'AuthProtocol': instance.AuthProto['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': str(varBindRow[0]), 'Value': str(varBindRow[1]), 'Status': "Success"})
                else:
                    #print(f"{varBindRow[0]} {varBindRow[1]}")
                    results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Username': instance.Username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': str(varBindRow[0]), 'Value': str(varBindRow[1]), 'Status': "Success"})
                
            if varBindRow[1].tagSet == EndOfMibView.tagSet or initialOID.isPrefixOf(varBindTable[-1][0]):
                break

    return results


# MARK: Main
async def main():
    parser = argparse.ArgumentParser(description='A modern and intelligent approach to SNMP hacking')
        
    module_group = parser.add_argument_group('Modules')
    #module_group.add_argument('--scan', action='store_true', help='Scan for SNMP services')
    module_group.add_argument('--spray', action='store_true', help='Spray any provided community strings, credentials (user/pass), and combos')
    #module_group.add_argument('--write', action='store_true', help='Check if write access is possible')
    module_group.add_argument('--bulkwalk', action='store_true', help='Collect as much information as possible')
    module_group.add_argument('--all', action='store_true', help='CAUTION: Use all above modules')

    auth_group = parser.add_argument_group('Spray Arguments')
    auth_group.add_argument('-c', '--community', type=str, help='Singular community string or file containing line-delimited strings')
    auth_group.add_argument('-u', '--username', type=str, help='Singular username or file containing line-delimited usernames')
    auth_group.add_argument('-p', '--password', type=str, help='Singular password or file containing line-delimited passwords') # Is used for auth and priv passwords/keys
    auth_group.add_argument('-ap', '--auth-proto', type=str, default='ANY', choices=['ANY', 'HMACMD5', 'HMACSHA', 'HMAC128SHA224', 'HMAC192SHA256', 'HMAC256SHA384', 'HMAC384SHA512'], help='Singular authentication protocol or try any of them')
    auth_group.add_argument('-pp', '--priv-proto', type=str, default='ANY', choices=['ANY', 'DES', 'AESCFB128', 'AESCFB192', 'AESCFB256'], help='Singular privacy protocol or try any of them')
    #auth_group.add_argument('-cb', '--combo', help='File containing line-delimited combos (host,port,username,password/string)')

    io_group = parser.add_argument_group('I/O Arguments')
    io_group.add_argument('-t', '--target', type=str, help='Singular hostname or IPv4/IPv6 address or file containing line-delimited targets')
    io_group.add_argument('-pt', '--port', default=161, help='Target port/range (e.g., 161 or 161,162 or 160-165)')
    io_group.add_argument('-i', '--interface', type=str, help='Specify network interface (e.g., eth0, Ethernet0)')
    io_group.add_argument('-eid', '--engine-id', type=str, help='Specify a hex agent engine ID (e.g., 0x80000000011234567890abcdef)')
    io_group.add_argument('-o', '--output', type=str, default='SNMPede_', help='CSV prepended output filename/path')
    io_group.add_argument('-d', '--debug', type=int, default=0, choices=[0, 1, 2], help='Debug level to stdout')
    io_group.add_argument('-to', '--timeout', type=float, default=3, help='Timeout seconds')
    io_group.add_argument('-rt', '--retries', type=int, default=0, help='Retries count')
    io_group.add_argument('-dl', '--delay', type=float, default=0.7, help='Seconds delay between each request')
    io_group.add_argument('-or', '--oid-read', type=str, default='1.3.6.1.2.1.1.1.0', help='OID the Spray module will read (default is sysDescr.0)')
    #io_group.add_argument('-ow', '--oid-write', type=str, default='', help='')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    await asyncio.sleep(0.2)

    ascii_art = """
.▄▄ ·  ▐ ▄ • ▌ ▄ ·.  ▄▄▄·▄▄▄ .·▄▄▄▄  ▄▄▄ .
▐█ ▀. •█▌▐█·██ ▐███▪▐█ ▄█▀▄.▀·██▪ ██ ▀▄.▀·
▄▀▀▀█▄▐█▐▐▌▐█ ▌▐▌▐█· ██▀·▐▀▀▪▄▐█· ▐█▌▐▀▀▪▄
▐█▄▪▐███▐█▌██ ██▌▐█▌▐█▪·•▐█▄▄▌██. ██ ▐█▄▄▌
 ▀▀▀▀ ▀▀ █▪▀▀  █▪▀▀▀.▀    ▀▀▀ ▀▀▀▀▀•  ▀▀▀ 
    """
    print(ascii_art)

    # Tier 2 debugging
    if args.debug >= 0:
        global argdebug
        argdebug = args.debug
    if argdebug == 2: debug.setLogger(debug.Debug('secmod', 'msgproc'))

    # MARK: Exception Checks
    if not args.target:
        print("[e] No target was provided. Please add one.")
        parser.print_help()
        quit()
    else:
        # Convert the singular or multiple targets to a list
        targets = await convert_to_list(args.target)
        if argdebug >= 1: print("[d] Detected the following:\n[d] " + str(len(targets)) + ' target(s)')
        tasks = []
        for target in targets: # Returns (FQDN, IP, Version)
            tasks.append(asyncio.create_task(resolve_target(target)))

    if not (args.spray or args.all): #args.scan
        print("[e] No module was selected. Please pick one:")
        parser.print_help()
        quit()

    # Wait for name resolution to finish before continuing
    try:
        resolved_targets = await asyncio.gather(*tasks)
    except Exception as e:
        print(f"[e] A resolution error occurred: {e}")
        quit()

    # Check interface existance and compatibility
    global interface_addr4, interface_addr6
    interface_addr4 = None
    interface_addr6 = None
    if args.interface:
        # Get network interface addresses
        interfaces = psutil.net_if_addrs()

        # Check if the NIC name exists in the addresses
        for interface_name, addresses in interfaces.items():
            if interface_name.lower() == (args.interface).lower():
                for address in addresses: # Single interface could have both an IPv4 and IPv6 address, or sadly multiple of each
                    if any('v4' in tup for tup in resolved_targets) and address.family == AF_INET:
                        interface_addr4 = address.address
                    elif any('v6' in tup for tup in resolved_targets) and address.family == AF_INET6:
                        interface_addr6 = address.address
        if not interface_addr4 and not interface_addr6:
            print("[e] Provided interface not found. Interfaces found:")
            for interface_name, addresses in interfaces.items():
                print("    '" + interface_name + "'")
            quit()
        elif any('v4' in tup for tup in resolved_targets) and not interface_addr4:
            print("[e] An IPv4 target was provided, but the provided interface does not support IPv4.")
            quit()
        elif any('v6' in tup for tup in resolved_targets) and not interface_addr6:
            print("[e] An IPv6 target was provided, but the provided interface does not support IPv6.")
            quit()
        elif argdebug >= 1:
            print(f"[d] NIC: {args.interface}")
            print(f"[d] IPv4 local address: {interface_addr4}")
            print(f"[d] IPv6 local address: {interface_addr6}")
    

    if args.spray or args.all:
        if not args.community and not args.username and not args.password:
            print("[e] Although the spray module was specified, neither a community, username, or password was provided. You may consider the Dictionaries/ provided.")
            parser.print_help()
            quit()
        else:
            global oid_read
            oid_read = args.oid_read

    if args.bulkwalk and not (args.spray or args.all):
        print("[e] The bulkwalk module requires the Spray or All modules.")
        quit()

    # Convert the singular or multiple ports to a list
    ports = await parse_ports(args.port)
    if argdebug >= 1: print("[d] " + str(len(ports)) + ' port(s)')

    if args.community:
        # Convert the singular or multiple community strings to a list
        community_strings = await convert_to_list(args.community)
        if argdebug >= 1: print("[d] " + str(len(community_strings)) + ' community string(s)')

    if args.username:
        # Convert the singular or multiple values to a list
        usernames = await convert_to_list(args.username)
        if argdebug >= 1: print("[d] " + str(len(usernames)) + ' username(s)')

    if args.all or (args.spray and args.password):
        if not args.username:
            print("[e] Password(s) detected, but no usernames detected. Please adjust.")
            quit()
        
        # Convert the singular or multiple passwords to a list
        passwords = await convert_to_list(args.password)
        if argdebug >= 1: print("[d] " + str(len(passwords)) + ' password(s)')

        # SNMP v3 does not allow less than 8 character passwords. Error if we have any
        if any(len(password) < 8 for password in passwords):
            print("[e] SNMP v3 does not allow passwords less than 8 characters. Please adjust.")
            quit()
    
    # Agent engine ID requires `0x`, make sure it does:
    if args.engine_id and not args.engine_id.startswith('0x'):
        print("[e] The agent engine ID must start with '0x'.")
        quit()
    else:
        global engine_id
        engine_id = args.engine_id

    # Map custom auth protocol to Name/Class
    auth_protocols = [
        {'Name': 'HMACMD5', 'Class': usmHMACMD5AuthProtocol},
        {'Name': 'HMACSHA', 'Class': usmHMACSHAAuthProtocol},
        {'Name': 'HMAC128SHA224', 'Class': usmHMAC128SHA224AuthProtocol},
        {'Name': 'HMAC192SHA256', 'Class': usmHMAC192SHA256AuthProtocol},
        {'Name': 'HMAC256SHA384', 'Class': usmHMAC256SHA384AuthProtocol},
        {'Name': 'HMAC384SHA512', 'Class': usmHMAC384SHA512AuthProtocol}
    ]
    if args.auth_proto != 'Any':
        for protocol in auth_protocols:
            if protocol['Name'] == args.auth_proto:
                auth_protocols = [protocol]
                break

    # Map custom priv protocol to Name/Class
    priv_protocols = [
        {'Name': 'DES', 'Class': usmDESPrivProtocol},
        {'Name': 'AESCFB128', 'Class': usmAesCfb128Protocol},
        {'Name': 'AESCFB192', 'Class': usmAesCfb192Protocol},
        {'Name': 'AESCFB256', 'Class': usmAesCfb256Protocol}
    ]
    if args.priv_proto != 'Any':
        for protocol in priv_protocols:
            if protocol['Name'] == args.priv_proto:
                priv_protocols = [protocol]
                break

    # MARK: Scan
    # if args.scan or args.all:
    #     if argdebug >=1: print() # For pretty stdout
    #     print("[i] Performing SNMP port scanning...")
    #     tasks = []
    #     for target in resolved_targets:
    #         for port in ports:
    #             print(f'[-] Scanning {target[0]}:{port}')
    #             tasks.append(scan_port(target, port, args.timeout))
        
    #     outputfile = args.output + 'Scan.csv'
    #     if not exists(outputfile):
    #         write_fieldnames(outputfile, 'Host,Protocol,Port,Service,Status\n')

    #     # Wait for port scanning to finish
    #     try:
    #         task_results = await asyncio.gather(*tasks)
    #     except Exception as e:
    #         print(f"[e] A scan error occurred: {e}")
    #         quit()

    #     print("[-] Writing results...")
    #     append_csv(outputfile, ['Host', 'Protocol', 'Port', 'Service', 'Status'], task_results)

    #     if len(Target.get_instances()) == 0:
    #         if args.spray or args.all:
    #             quit_text = ' Quitting...'
    #         else:
    #             quit_text = ''
    #         print(f"[i] No open port(s) found{quit_text}.\n")
    #         quit()
    #     else:
    #         print() # For pretty stdout


    # MARK: Comm_Strings
    if args.spray or args.all:
        if args.community:
            if argdebug >=1: print() # For pretty stdout #  and not args.scan
            print("[i] Spraying SNMP versions 1/2c community string(s)...")
            tasks = []
            task_results = []
            
            # Doing async like this so that we don't DDOS a specific SNMP agent
            if len(Target.get_instances()) > 0:
                if argdebug >= 1: print(f"[d] Using the existing ({len(Target.get_instances())}) instances")
                
                for instance in Target.get_instances():
                    tasks.append(asyncio.create_task(snmp_v12c_get(instance.FQDN, instance.port, 'v1', args.timeout, args.retries, args.delay, community_strings, instance=instance)))
                    tasks.append(asyncio.create_task(snmp_v12c_get(instance.FQDN, instance.port, 'v2c', args.timeout, args.retries, args.delay, community_strings, instance=instance)))

            else:
                for target in resolved_targets:
                    for port in ports:
                        tasks.append(asyncio.create_task(snmp_v12c_get(target, port, 'v1', args.timeout, args.retries, args.delay, community_strings)))
                        tasks.append(asyncio.create_task(snmp_v12c_get(target, port, 'v2c', args.timeout, args.retries, args.delay, community_strings)))
            
            outputfile = args.output + 'v12c_Spray_Community_Strings.csv'
            if not exists(outputfile):
                write_fieldnames(outputfile, 'Host,Port,Version,CommunityString,OID,Value,Status\n')

            # Wait for community string spraying to finish
            try:
                task_results.extend(await asyncio.gather(*tasks))
            except Exception as e:
                print(f"[e] A community string spraying error occurred: {e}")
                quit()

            print("[-] Writing results...")
            for r in task_results:
                append_csv(outputfile, ['Host', 'Port', 'Version', 'CommunityString', 'OID', 'Value', 'Status'], r)
            
            if len(Target.get_instances()) == 0:
                print(f"[i] No community string(s) found.\n")
                quit()
            else:
                print() # For pretty stdout

        
        # MARK: UserEnum
        if args.username:
            if argdebug >=1 and not args.community: print() # For pretty stdout # (args.scan or args.community)
            print("[i] Spraying SNMP v3 username(s) with NoAuthNoPriv...")
            tasks = []
            task_results = []
            
            # Doing async like this so that we don't DDOS a specific SNMP agent
            instances = get_instances_with_attribute(Target.get_instances(), 'Access', False)
            if instances:
                if argdebug >= 1: print(f"[d] Using the relevant ({len(instances)}) instances")
                for instance in instances:
                    tasks.append(asyncio.create_task(snmp_v3_get(instance.FQDN, instance.Port, args.timeout, args.retries, args.delay, usernames, instance=instance)))
            else:
                for target in resolved_targets:
                    for port in ports:
                        tasks.append(asyncio.create_task(snmp_v3_get(target, port, args.timeout, args.retries, args.delay, usernames)))
            
            outputfile = args.output + 'v3_Spray_Credentials.csv'
            if not exists(outputfile):
                write_fieldnames(outputfile, 'Host,Port,Version,Username,AuthPassword,AuthProtocol,PrivPassword,PrivProtocol,OID,Value,Status\n')

            # Wait for username spraying to finish
            try:
                task_results.extend(await asyncio.gather(*tasks))
            except Exception as e:
                print(f"[e] A username spraying error occurred: {e}")
                quit()

            print("[-] Writing results...")
            for r in task_results:
                append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
            
            if len(Target.get_instances()) == 0 or len(get_instances_with_attribute(Target.get_instances(), 'Username')) == 0:
                print(f"[i] No username(s) found.\n")
                quit()
            else:
                print() # For pretty stdout


        # MARK: AuthPwd
        if args.password:
            print("[i] Spraying SNMP v3 password(s) with AuthNoPriv...")
            tasks = []
            task_results = []
            
            # Doing async like this so that we don't DDOS a specific SNMP agent
            # Filter for any unfinished targets
            instances = get_instances_with_attribute(Target.get_instances(), 'Access', False)
            # Filter for those with Username not None
            instances = get_instances_with_attribute(instances, 'Username')
            if argdebug >= 1: print(f"[d] Using the relevant ({len(instances)}) instances")

            for instance in instances:
                tasks.append(asyncio.create_task(snmp_v3_get(instance.FQDN, instance.Port, args.timeout, args.retries, args.delay, instance.Username, authpasswords=passwords, authprotocols=auth_protocols, instance=instance)))

            # Wait for auth spraying to finish
            try:
                task_results.extend(await asyncio.gather(*tasks))
            except Exception as e:
                print(f"[e] An AuthNoPriv spraying error occurred: {e}")
                error_details = traceback.format_exc()
                print(f"Full traceback:\n{error_details}")
                quit()

            print("[-] Writing results...")
            for r in task_results:
                append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
            
            if len(Target.get_instances()) == 0 or len(get_instances_with_attribute(Target.get_instances(), 'AuthPwd')) == 0:
                print(f"[i] No AuthNoPriv password(s) found.\n")
                quit()
            else:
                print() # For pretty stdout


            # MARK: PrivPwd
            # Doing async like this so that we don't DDOS a specific SNMP agent
            # Filter for any unfinished targets
            instances = get_instances_with_attribute(Target.get_instances(), 'Access', False)
            # Filter for those with AuthPwd not None
            instances = get_instances_with_attribute(instances, 'AuthPwd')
            if instances:
                print("[i] Spraying SNMP v3 password(s) with AuthPriv...")
                tasks = []
                task_results = []
                if argdebug >= 1: print(f"[d] Using the relevant ({len(instances)}) instances")
                for instance in instances:
                    tasks.append(asyncio.create_task(snmp_v3_get(instance.FQDN, instance.Port, args.timeout, args.retries, args.delay, instance.Username, authpasswords=instance.AuthPwd, authprotocols=instance.AuthProto, privpasswords=passwords, privprotocols=priv_protocols, instance=instance)))

                # Wait for AuthPriv spraying to finish
                try:
                    task_results.extend(await asyncio.gather(*tasks))
                except Exception as e:
                    print(f"[e] An AuthPriv spraying error occurred: {e}")
                    quit()

                print("[-] Writing results...")
                for r in task_results:
                    append_csv(outputfile, ['Host', 'Port', 'Version', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)
                
                if len(Target.get_instances()) == 0 or len(get_instances_with_attribute(Target.get_instances(), 'PrivPwd')) == 0:
                    print(f"[i] No AuthPriv password(s) found.\n")
                else:
                    print() # For pretty stdout
            else:
                print("[i] Skipping spraying AuthPriv as its unnecessary...\n")

        # We need to cleanse no Access instances so that our post-access
        # activities can be efficient
        for instance in Target.get_instances():
            if instance.Access == False:
                del instance


    # MARK: bulkwalk
    if args.bulkwalk or args.all:
        if not Target.get_instances():
            print("[i] No successful access was achieved. Skipping BulkWalk")
        else:        
            # Doing async like this so that we don't DDOS a specific SNMP agent
            instances = get_instances_with_attribute(Target.get_instances(), 'CommunityString')
            if instances:
                tasks = []
                task_results = []
                print("[i] Walking in bulk v1/2c information...")
                if argdebug >= 1: print(f"[d] Using the relevant ({len(instances)}) v1/2c instances")
                for instance in instances:
                    tasks.append(asyncio.create_task(snmp_v12c_bulkwalk(instance, args.timeout, args.retries, args.delay)))
            
                outputfile = args.output + 'v12c_BulkWalk.csv'
                if not exists(outputfile):
                    write_fieldnames(outputfile, 'Host,Port,Version,CommunityString,OID,Value,Status\n')

                # Wait for bulkwalk to finish
                try:
                    task_results.extend(await asyncio.gather(*tasks))
                except Exception as e:
                    print(f"[e] A v1/2c bulkwalk error occurred: {e}")
                    traceback.print_exc()  # Print the full traceback
                    quit()

                print("[-] Writing results...\n")
                for r in task_results:
                    if r:
                        append_csv(outputfile, ['Host', 'Port', 'Version', 'CommunityString', 'OID', 'Value', 'Status'], r)

            instances = get_instances_with_attribute(Target.get_instances(), 'Username')
            if instances:
                tasks = []
                task_results = []
                print("[i] Walking in bulk v3 information...")
                if argdebug >= 1: print(f"[d] Using the relevant ({len(instances)}) v3 instances")
                for instance in instances:
                    tasks.append(asyncio.create_task(snmp_v3_bulkwalk(instance, args.timeout, args.retries, args.delay)))
            
                outputfile = args.output + 'v3_BulkWalk.csv'
                if not exists(outputfile):
                    write_fieldnames(outputfile, 'Host,Port,Username,AuthPassword,AuthProtocol,PrivPassword,PrivProtocol,OID,Value,Status\n')

                # Wait for bulkwalk to finish
                try:
                    task_results.extend(await asyncio.gather(*tasks))
                except Exception as e:
                    print(f"[e] A v3 bulkwalk error occurred: {e}")
                    traceback.print_exc()  # Print the full traceback
                    quit()

                print("[-] Writing results...\n")
                for r in task_results:
                    append_csv(outputfile, ['Host', 'Port', 'Username', 'AuthPassword', 'AuthProtocol', 'PrivPassword', 'PrivProtocol', 'OID', 'Value', 'Status'], r)


if __name__ == '__main__':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print('[e] Program termination requested by user')