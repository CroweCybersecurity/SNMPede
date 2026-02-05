from _modules import config
from pysnmp.hlapi.v1arch.asyncio import *
import asyncio
from _modules.classes import Target

# MARK: v1/2c Get_Multi
# Multi means multiple hosts


async def snmp_v12c_get_multi(
        semaphore,
        task_id,
        target,
        port,
        snmp_version,
        community_strings,
        instance=None):
    async with semaphore:
        if config.ARGDEBUG >= 1:
            print(f"[d] Acquired {snmp_version} task {task_id}")

        success = False
        Target_instances = []
        results = []

        await asyncio.sleep(config.ARGDELAY)

        # SNMPv1 is mpModel 0, SNMPv2c is mpModel 1. Note that 2c often is
        # backwards compatible
        mpModel = 0 if snmp_version == 'v1' else 1

        if target[2] == 'v4':
            transport_target = await UdpTransportTarget.create(
                (target[0], port), config.ARGTIMEOUT, config.ARGRETRIES
            )
        else:
            transport_target = await Udp6TransportTarget.create(
                (target[0], port), config.ARGTIMEOUT, config.ARGRETRIES
            )

        # Bind to NIC IP address
        if config.INTERFACE_ADDR4 is not None:
            transport_target.transportDomain = (config.INTERFACE_ADDR4, 0)
        elif config.INTERFACE_ADDR6 is not None:
            transport_target.transportDomain = (config.INTERFACE_ADDR6, 0)

        # Create a single SnmpDispatcher instance
        snmpDispatcher = SnmpDispatcher()

        try:
            for community_string in community_strings:
                if config.ARGDEBUG >= 1:
                    print(
                        f"[d] '{community_string}' -> "
                        f"{target[0]}:{port}/{snmp_version}"
                    )

                await asyncio.sleep(config.ARGDELAY)

                (errorIndication,
                 errorStatus,
                 errorIndex,
                 varBinds) = await get_cmd(
                    snmpDispatcher,
                    CommunityData(community_string, mpModel=mpModel),
                    transport_target,
                    ObjectType(ObjectIdentity(config.OID_READ)),
                )

                if errorIndication:
                    if config.ARGDEBUG >= 1:
                        print(f"[d] Error: {errorIndication}")
                    results.append({
                        'Host': target[0],
                        'Port': port,
                        'Version': snmp_version,
                        'CommunityString': community_string,
                        'OID': config.OID_READ,
                        'Value': None,
                        'Status': f"Error: {errorIndication}"
                    })
                elif errorStatus:
                    if config.ARGDEBUG >= 1:
                        print(f"[d] Error: {errorStatus.prettyPrint()}")
                    results.append({
                        'Host': target[0],
                        'Port': port,
                        'Version': snmp_version,
                        'CommunityString': community_string,
                        'OID': config.OID_READ,
                        'Value': None,
                        'Status': f"Error: {errorStatus.prettyPrint()}"
                    })
                else:
                    print(
                        f"[!] Found '{community_string}' at "
                        f"{target[0]}:{port}/{snmp_version}"
                    )
                    if not instance or success is True:
                        new_target = Target(
                            target[0], target[1], target[2], port,
                            SNMPVersion=snmp_version,
                            CommunityString=community_string,
                            Access=True
                        )
                        if not any(
                            t.FQDN == new_target.FQDN and
                            t.Port == new_target.Port and
                            t.SNMPVersion == new_target.SNMPVersion and
                            t.CommunityString == new_target.CommunityString
                            for t in Target_instances
                        ):
                            Target_instances.append(new_target)
                        success = True
                    else:
                        # Do NOT mutate the instance's SNMPVersion or
                        # CommunityString!
                        new_target = Target(
                            instance.FQDN,
                            instance.IP,
                            instance.IPVersion,
                            instance.Port,
                            SNMPVersion=snmp_version,
                            CommunityString=community_string,
                            Access=True)
                        if not any(
                            t.FQDN == new_target.FQDN and
                            t.Port == new_target.Port and
                            t.SNMPVersion == new_target.SNMPVersion and
                            t.CommunityString == new_target.CommunityString
                            for t in Target_instances
                        ):
                            Target_instances.append(new_target)
                        success = True

                    for varBind in varBinds:
                        results.append({
                            'Host': target[0],
                            'Port': port,
                            'Version': snmp_version,
                            'CommunityString': community_string,
                            'OID': config.OID_READ,
                            'Value': str(varBind),
                            'Status': "Success"
                        })

        finally:
            # Close the dispatcher after all requests
            snmpDispatcher.transport_dispatcher.close_dispatcher()

        if success is False and instance:
            del instance

        if config.ARGDEBUG >= 1:
            print(f"[d] Released {snmp_version} task {task_id}")
        return results, Target_instances
