from os.path import exists
from socket import getaddrinfo, gaierror, AF_INET, AF_INET6
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from re import compile
from _modules import config
from asyncio import CancelledError

fqdn_regex = compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$')


async def resolve_target(target: str) -> tuple:
    """Resolve a target to (FQDN, IP, Version)."""
    try:
        IPv4Address(target)
        return (target, target, "v4")
    except AddressValueError:
        pass

    try:
        IPv6Address(target)
        return (target, target, "v6")
    except AddressValueError:
        pass

    if fqdn_regex.match(target):
        try:
            addr_info = getaddrinfo(target, None)
            if addr_info:
                first_info = addr_info[0]
                if first_info[0] == AF_INET:
                    return (target, first_info[4][0], 'v4')
                elif first_info[0] == AF_INET6:
                    return (target, first_info[4][0], 'v6')
        except gaierror:
            pass

    return (None, None, None)


async def convert_to_list(param: str) -> list:
    """Convert a file or string to a unique list of strings."""
    if exists(param):
        config.WASFILEIMPORTED = True
        with open(param, 'r') as file:
            param_list = [line.strip() for line in file.readlines()]
            seen = set()
            return [x for x in param_list if not (x in seen or seen.add(x))]
    else:
        return [param]


async def parse_ports(ports) -> list:
    """Parse a port string or int into a list of ints."""
    port_list = []
    if isinstance(ports, int):
        return [ports]
    for part in ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))
    return port_list


def get_instances_with_attribute(instances: list, attribute_name: str, attribute_value=None) -> list:
    """Return instances with a given attribute set (optionally to a specific value)."""
    matching_instances = []
    for instance in instances:
        if attribute_value is not None:
            if hasattr(instance, attribute_name) and getattr(instance, attribute_name) == attribute_value:
                matching_instances.append(instance)
        else:
            if hasattr(instance, attribute_name) and getattr(instance, attribute_name) is not None:
                matching_instances.append(instance)
    return matching_instances


def handle_task_result(task) -> None:
    """Surface real task exceptions, but ignore normal cancellations (Ctrl+C/shutdown)."""
    try:
        exc = task.exception()
    except CancelledError:
        # Expected during shutdown; don't spam tracebacks
        return

    if exc:
        print(f"Task exception: {exc!r}")