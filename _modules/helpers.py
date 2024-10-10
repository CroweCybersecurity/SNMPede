from os.path import exists
from socket import getaddrinfo, gaierror, AF_INET, AF_INET6
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from re import compile

global fqdn_regex
fqdn_regex = compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$')

async def resolve_target(target):
    # The first section here checks to see if the target is an IPv4 or IPv6 address string
    # If it is an IP, return. No need to resolve an IP.

    try:
        # Check if it's an IPv4 address
        IPv4Address(target)
        return (target, target, "v4") # FQDN, IP, Version
    except AddressValueError:
        # We can pass as the target may fit the next if statements
        pass

    try:
        # Check if it's an IPv6 address
        IPv6Address(target)
        return (target, target, "v6") # FQDN, IP, Version
    except AddressValueError:
        # We can pass as the target may fit the next if statements
        pass

    # If it's a FQDN, resolve it and make a IP version determination
    # based upon the first resolved record.
    if fqdn_regex.match(target):
        try:
            addr_info = getaddrinfo(target, None)
            if addr_info:
                first_info = addr_info[0]
                if first_info[0] == AF_INET: # IPv4
                    return (target, first_info[4][0], 'v4')
                elif first_info[0] == AF_INET6: # IPv6
                    return (target, first_info[4][0], 'v6')
        except gaierror:
            # We can pass as the next return will announce the failure.
            pass

    return (None, None, None)


# MARK: Helpers
async def convert_to_list(param):
    # Check if the param is an existing file
    if exists(param):
        with open(param, 'r') as file:
            # Read the file into a list, stripping newline characters
            param_list = [line.strip() for line in file.readlines()]
            # Remove duplicates
            seen = set()
            return [x for x in param_list if not (x in seen or seen.add(x))]
    else:
        return [param]


async def parse_ports(ports):
    port_list = []
    # If a single port was provided
    if type(ports) == int: return [ports]
    # If more than one port was provided
    for part in ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))
    return port_list


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