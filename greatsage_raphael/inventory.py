"""Loads and validates an optional local network inventory."""
import ipaddress
import json
import re


def load_inventory(path):
    with open(path,'rb') as source:
        raw=source.read(65537)
    if len(raw)>65536:raise ValueError('Inventory exceeds 64 KiB.')
    try:data=json.loads(raw)
    except (RecursionError,UnicodeDecodeError) as exc:raise ValueError('Invalid or excessively nested inventory JSON.') from exc
    if not isinstance(data,dict) or set(data)-{'arp_bindings','dhcp_servers','dns_records'}:
        raise ValueError('Inventory keys: arp_bindings, dhcp_servers, dns_records only.')
    result={'arp_bindings':{},'dhcp_servers':[],'dns_records':{}}
    def addresses(values):
        if not isinstance(values,list) or not values or len(values)>64:raise ValueError('Expected a nonempty list of up to 64 addresses.')
        if any(not isinstance(v,str) for v in values):raise ValueError('Inventory addresses must be strings.')
        return [str(ipaddress.ip_address(v)) for v in values]
    for key in ('arp_bindings','dns_records'):
        mapping=data.get(key,{})
        if not isinstance(mapping,dict) or len(mapping)>1000:raise ValueError('Inventory mappings are limited to 1,000 entries.')
        for name,values in mapping.items():
            if key=='arp_bindings':
                name=str(ipaddress.IPv4Address(name))
                if not isinstance(values,list) or not values or len(values)>64:raise ValueError('Expected a list of MAC addresses.')
                if any(not isinstance(v,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',v) for v in values):raise ValueError('Invalid inventory MAC address.')
                result[key][name]=[v.lower() for v in values]
            else:
                if not isinstance(name,str) or not name or len(name)>253:raise ValueError('Invalid inventory DNS name.')
                result[key][name.lower().rstrip('.')]=addresses(values)
    servers=data.get('dhcp_servers',[])
    if servers:result['dhcp_servers']=addresses(servers)
    elif not isinstance(servers,list):raise ValueError('DHCP servers must be a list.')
    return result
