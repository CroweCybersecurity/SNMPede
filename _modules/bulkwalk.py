from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto import rfc1902
from _modules import config
import asyncio


# MARK: v1/2c
async def snmp_v12c_bulkwalk(instance):
    results = []
    if config.ENGINE_ID:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=config.ENGINE_ID))
    else:
        snmpEngine = SnmpEngine()
    
    if instance.IPVersion == 'v4':
        transport_target = await UdpTransportTarget.create((instance.FQDN, instance.Port), config.ARGTIMEOUT, config.ARGRETRIES)
    else:
        transport_target = await Udp6TransportTarget.create((instance.FQDN, instance.Port), config.ARGTIMEOUT, config.ARGRETRIES)
    
    # Bind to NIC IP address
    if config.INTERFACE_ADDR4 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR4, 0)
    elif config.INTERFACE_ADDR6 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR6, 0)

    await asyncio.sleep(config.ARGDELAY)

    if instance.SNMPVersion == 'v1':
        mpModel = 0
        print("[i] Skipping a v1 instance due to lack of bulkwalk compatibility [COMING SOON!]")
        return None
    else:
        mpModel = 1
        if config.ARGDEBUG >= 1: print(f"[d] '{instance.CommunityString}' -> {instance.FQDN}:{instance.Port}/{instance.SNMPVersion}")

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
            if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
            results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Version': instance.SNMPVersion, 'CommunityString': instance.CommunityString, 'OID': None, 'Value': None, 'Status': f"Error: {errorStatus.prettyPrint()}"})
        else:
            #print(f"[!] Found data at '{instance.FQDN}:{instance.Port}/{instance.SNMPVersion}/{instance.Username}")
            for varBindRow in varBindTable:
                #print(f"{varBindRow[0]} {varBindRow[1]}")
                results.append({'Host': instance.FQDN, 'Port': instance.Port, 'Version': instance.SNMPVersion, 'CommunityString': instance.CommunityString, 'OID': str(varBindRow[0]), 'Value': str(varBindRow[1]), 'Status': "Success"})
                
            if varBindRow[1].tagSet == EndOfMibView.tagSet or initialOID.isPrefixOf(varBindTable[-1][0]):
                break

    return results


# MARK: v3
async def snmp_v3_bulkwalk(instance):
    results = []
    if config.ENGINE_ID:
        snmpEngine = SnmpEngine(snmpEngineID=OctetString(hexValue=config.ENGINE_ID))
    else:
        snmpEngine = SnmpEngine()
    
    if instance.IPVersion == 'v4':
        transport_target = await UdpTransportTarget.create((instance.FQDN, instance.Port), config.ARGTIMEOUT, config.ARGRETRIES)
    else:
        transport_target = await Udp6TransportTarget.create((instance.FQDN, instance.Port), config.ARGTIMEOUT, config.ARGRETRIES)
    
    # Bind to NIC IP address
    if config.INTERFACE_ADDR4 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR4, 0)
    elif config.INTERFACE_ADDR6 is not None:
        transport_target.transportDomain = (config.INTERFACE_ADDR6, 0)

    await asyncio.sleep(config.ARGDELAY)

    if instance.PrivProto:
        if config.ARGDEBUG >= 1: print(f"[d] '{instance.Username}/{instance.AuthPwd}/{instance.AuthProto['Name']}/{instance.PrivPwd}/{instance.PrivProto['Name']}' -> {instance.FQDN}:{instance.Port}")
        usmuserdata = UsmUserData(userName=instance.Username, authKey=instance.AuthPwd, authProtocol=instance.AuthProto['Class'], privKey=instance.PrivPwd, privProtocol=instance.PrivProto['Class'])
    elif instance.AuthProto:
        if config.ARGDEBUG >= 1: print(f"[d] '{instance.Username}/{instance.AuthPwd}/{instance.AuthProto['Name']}' -> {instance.FQDN}:{instance.Port}")
        usmuserdata = UsmUserData(userName=instance.Username, authKey=instance.AuthPwd, authProtocol=instance.AuthProto['Class'])
    else:
        if config.ARGDEBUG >= 1: print(f"[d] '{instance.Username}' -> {instance.FQDN}:{instance.Port}")
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
            if config.ARGDEBUG >= 1: print(f"[d] Error: {errorStatus.prettyPrint()}")
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