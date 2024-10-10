from _modules.config import *
from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from SNMPede import Target

# MARK: v1/2c Login
async def snmp_v12c_get_multi(target, port, version, timeout, retries, delay, community_strings, instance=None):
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


# MARK: v3 Login
async def snmp_v3_get_multi(target, port, timeout, retries, delay, usernames, authpasswords=None, authprotocols=None, privpasswords=None, privprotocols=None, instance=None):
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