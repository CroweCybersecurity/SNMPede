from _modules import config
from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from snmpede import Target

# MARK: v1/2c Get_Multi
async def snmp_v12c_get_multi(target, port, snmp_version, community_strings, instance=None):
    success = False
    Target_instances = []

    results = []
    if config.ENGINE_ID:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=config.ENGINE_ID))
    else:
        snmpEngine = SnmpEngine()
    
    await asyncio.sleep(config.ARGDELAY)

    mpModel = 0 if snmp_version == 'v1' else 1  # SNMPv1 is mpModel 0, SNMPv2c is mpModel 1. Note that 2c often is backwards compatible
    for community_string in community_strings:
        if config.ARGDEBUG >= 1: print(f"[d] '{community_string}' -> {target[0]}:{port}/{snmp_version}")

        if target[2] == 'v4':
            transport_target = await UdpTransportTarget.create((target[0], port), config.ARGTIMEOUT, config.ARGRETRIES)
        else:
            transport_target = await Udp6TransportTarget.create((target[0], port), config.ARGTIMEOUT, config.ARGRETRIES)
        
        # Bind to NIC IP address
        if config.INTERFACE_ADDR4 is not None:
            transport_target.transportDomain = (config.INTERFACE_ADDR4, 0)
        elif config.INTERFACE_ADDR6 is not None:
            transport_target.transportDomain = (config.INTERFACE_ADDR6, 0)

        await asyncio.sleep(config.ARGDELAY)

        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            snmpEngine,
            CommunityData(community_string, mpModel=mpModel),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(config.OID_READ))
        )

        if errorIndication:
            if config.ARGDEBUG >= 1: print(f"[d] Error: {errorIndication}")
            results.append({'Host': target[0], 'Port': port, 'Version': snmp_version, 'CommunityString': community_string, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorIndication}"})
        elif errorStatus:
            if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
            results.append({'Host': target[0], 'Port': port, 'Version': snmp_version, 'CommunityString': community_string, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
        else:
            print(f"[!] Found '{community_string}' at {target[0]}:{port}/{snmp_version}")
            if not instance or success is True:
                Target_instances.append(Target(target[0], target[1], target[2], port, SNMPVersion=snmp_version, CommunityString=community_string, Access=True))
                success = True
            else:
                instance.SNMPVersion = snmp_version
                instance.CommunityString = community_string
                instance.Access = True
                success = True
            
            for varBind in varBinds:
                results.append({'Host': target[0], 'Port': port, 'Version': snmp_version, 'CommunityString': community_string, 'OID': config.OID_READ, 'Value': str(varBind), 'Status': "Success"})
    
    if success is False and instance:
        del instance

    # [{Host, Port, Version, Community, OID, Value, Status}]
    return results, Target_instances


# MARK: v3 NoAuthNoPriv
async def snmp_v3_get_multi(target, port, usernames, authpasswords=None, authprotocols=None, privpasswords=None, privprotocols=None, instance=None):
    # CAUTION:
    # Usernames/auth/priv-passwords/auth/priv-protocols parameters above are used interchangeably in singular and multiple forms for ease of programming
    
    # For username spraying: defined as finding a username in any capacity
    success = False
    Target_instances = []

    results = []
    if config.ENGINE_ID:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=config.ENGINE_ID))
    else:
        snmpEngine = SnmpEngine()
    
    if target[2] == 'v4':
        transport_target = await UdpTransportTarget.create((target[0], port), config.ARGTIMEOUT, config.ARGRETRIES)
    else:
        transport_target = await Udp6TransportTarget.create((target[0], port), config.ARGTIMEOUT, config.ARGRETRIES)
    
    # Bind to NIC IP address
    if config.INTERFACE_ADDR4 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR4, 0)
    elif config.INTERFACE_ADDR6 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR6, 0)

    await asyncio.sleep(config.ARGDELAY)

    if type(usernames) == list:
        for username in usernames:
            if config.ARGDEBUG >= 1: print(f"[d] '{username}' -> {target[0]}:{port}")
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                snmpEngine,
                UsmUserData(userName=username),
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(config.OID_READ)) 
            )
            if errorIndication:
                if "Wrong SNMP PDU digest" in str(errorIndication) or "Unsupported SNMP security level" in str(errorIndication):
                    print(f"[!] Found '{username}' at {target[0]}:{port}")

                    if not instance or success is True:
                        Target_instances.append(Target(target[0], target[1], target[2], port, SNMPVersion='v3', Username=username))
                        success = True
                    else:
                        instance.SNMPVersion = 'v3'
                        instance.Username = username
                        # Because we are not setting Target.Access = True and it is still false with a Username,
                        # we tell future processses that NoAuthNoPriv was not sufficient, more is needed.
                        success = True

                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"User Discovered: {errorIndication}"})
                else:
                    if config.ARGDEBUG >= 1: print(f"[d] Error: {errorIndication}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorIndication}"})
            elif errorStatus:
                if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
            else:
                print(f"[!] Found '{username}' at {target[0]}:{port}")
                if not instance or success is True:
                    Target_instances.append(Target(target[0], target[1], target[2], port, SNMPVersion='v3', Username=username, Access=True))
                    success = True
                else:
                    instance.SNMPVersion = 'v3'
                    instance.Username = username
                    instance.Access = True
                    success = True

                for varBind in varBinds:
                    if config.ARGDEBUG >= 1: print(f"[d] Success: {varBind}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': username, 'AuthPassword': None, 'AuthProtocol': None, 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': str(varBind), 'Status': "Success"})
        return results, Target_instances
    
    elif not privpasswords: # MARK: #v3 AuthNoPriv
        for password in authpasswords:
            for protocol in authprotocols:
                if config.ARGDEBUG >= 1: print(f"[d] '{usernames}/{password}/{protocol['Name']}' -> {target[0]}:{port}")
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    snmpEngine,
                    UsmUserData(userName=usernames, authKey=password, authProtocol=protocol['Class']),
                    transport_target,
                    ContextData(),
                    ObjectType(ObjectIdentity(config.OID_READ))
                )
                if errorIndication:
                    if "Wrong SNMP PDU digest" in str(errorIndication):
                        results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Wrong Pwd/Algo: {errorIndication}"})
                    elif "Unsupported SNMP security level" in str(errorIndication):
                        print(f"[!] Found '{usernames}/{password}/{protocol['Name']}' at {target[0]}:{port}, but need Privacy")
                        results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Correct Auth, But Need Privacy: {errorIndication}"})
                        
                        instance.AuthPwd = password
                        instance.AuthProto = protocol
                        # No reason to keep auth guessing if the authpwd has been guessed
                        return results
                    else:
                        results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorIndication}"})
                elif errorStatus:
                    if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
                else:
                    print(f"[!] Found '{usernames}/{password}/{protocol['Name']}' at {target[0]}:{port}")
                    instance.AuthPwd = password
                    instance.AuthProto = protocol
                    instance.Access = True

                    for varBind in varBinds:
                        if config.ARGDEBUG >= 1: print(f"[d] Success: {varBind}")
                        results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': password, 'AuthProtocol': protocol['Name'], 'PrivPassword': None, 'PrivProtocol': None, 'OID': config.OID_READ, 'Value': str(varBind), 'Status': "Success"})
                    # No reason to keep auth guessing if the authpwd has been guessed
                return results
    
    else: # MARK: #v3 AuthPriv
        for password in privpasswords:
            for protocol in privprotocols:
                if config.ARGDEBUG >= 1: print(f"[d] '{usernames}/{authpasswords}/{authprotocols['Name']}/{password}/{protocol['Name']}' -> {target[0]}:{port}")
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    snmpEngine,
                    UsmUserData(userName=usernames, authKey=authpasswords, authProtocol=authprotocols['Class'], privKey=password, privProtocol=protocol['Class']),
                    transport_target,
                    ContextData(),
                    ObjectType(ObjectIdentity(config.OID_READ))
                )

                if errorIndication:
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorIndication}"})
                elif errorStatus:
                    if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
                    results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': config.OID_READ, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
                else:
                    print(f"[!] Found '{usernames}/{authpasswords}/{authprotocols['Name']}/{password}/{protocol['Name']}' at {target[0]}:{port}")
                    instance.PrivPwd = password
                    instance.PrivProto = protocol
                    instance.Access = True

                    for varBind in varBinds:
                        if config.ARGDEBUG >= 1: print(f"[d] Success: {varBind}")
                        results.append({'Host': target[0], 'Port': port, 'Version': 'v3', 'Username': usernames, 'AuthPassword': authpasswords, 'AuthProtocol': authprotocols['Name'], 'PrivPassword': password, 'PrivProtocol': protocol['Name'], 'OID': config.OID_READ, 'Value': str(varBind), 'Status': "Success"})
                    # No reason to keep auth guessing if the privpwd has been guessed
                    return results
    return results