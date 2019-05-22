import yaml
import sys
import struct

def aob2ip(bytes):
    return '.'.join([str(int(x,base=16)) for x in bytes])

def aob2mac(bytes):
    return ':'.join(bytes)

def aob2int(bytes):
    return int(aob2bytes(bytes),base=16)

def aob2bytes(bytes):
    return ''.join(bytes)

def aob2str(bytes):
    return ''.join([chr(x) for x in bytes])

def aob2hex(bytes):
    return f'0x{aob2bytes(bytes)}'

def aob2header(bytes):
    bytes=''.join(bytes)
    return aob2int(bytes[1])*4

def ethertype(bytes):
    bytes=aob2bytes(bytes)
    types={
        '0800':'IPv4',
        '0806':'ARP',
        '86dd':'IPv6'
    }
    return types.get(bytes,bytes)

def protocols(b):
    b=''.join(b)
    types={
        '06':'TCP',
        '11':'UDP',
        '01':'ICMP',
        '02':'IGMP'
    }
    return types.get(b,aob2hex(b))

def parseYAML(packet,raw):
    structure=packet['structure']
    psize=packet['size']
    funcmap = {
        'ip':aob2ip,
        'mac':aob2mac,
        'int':aob2int,
        'str':aob2str,
        'hex':aob2hex,
        'header':aob2header,
        'ethertype':ethertype,
        'protocol':protocols
    }
    aob=['{:02x}'.format(x) for x in struct.unpack(f'!{psize}B',raw)]
    index=0
    for n in structure:
        cmd=structure[n]
        strsplit=cmd.split('(')
        func=strsplit[0]
        size=int(strsplit[1][:-1])
        structure[n]=funcmap[func](aob[index:index+size])
        index+=size
    return structure

def load(protocol,raw):
    with open(f'Packets/{protocol.lower()}.yaml') as f:
        try:
            packet = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f'Error in YAML file {protocol.lower()}: {e}')
            sys.exit(0)
    return parseYAML(packet,raw)