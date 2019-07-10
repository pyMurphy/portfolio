import struct

def aob2ip(bytes):
    return '.'.join([str(int(x,base=16)) for x in bytes])

def aob2mac(bytes):
    return ':'.join(bytes)

def aob2int(bytes):
    return int(aob2str(bytes),base=16)

def aob2str(bytes):
    return ''.join(bytes)

def aob2hex(bytes):
    return f'0x{aob2str(bytes)}'

def ethertype(bytes):
    bytes=aob2str(bytes)
    types={
        '0800':'IPv4',
        '0806':'ARP',
        '86dd':'IPv6'
    }
    return types.get(bytes,bytes)

def protocols(b):
    types={
        '06':'TCP',
        '11':'UDP',
        '01':'ICMP',
        '02':'IGMP'
    }
    return types.get(b,aob2hex(b))

def header(type, data):
    ipv4 = {
        'Version':aob2int(ipv4[0][0]),
        'Header length':aob2int(ipv4[0][1])*4,
        'Differentiated Services Field':aob2hex(ipv4[1]),
        'Total Length':aob2int(ipv4[2:4]),
        'Identification':aob2hex(ipv4[4:6]),
        'Flags':aob2hex(ipv4[6:8]),
        'Time to live':aob2int(ipv4[8]),
        'Protocol':protocols(ipv4[9]),
        'Header checksum':aob2hex(ipv4[10:12]),
        'Source':aob2ip(ipv4[12:16]),
        'Destination':aob2ip(ipv4[16:20])
    }

class packet:
    def __init__(self,raw):
        self.raw=raw
        self.data=['{:02x}'.format(x) for x in struct.unpack(f'!{len(self.raw)}B',self.raw)]
        self.content=self.deconstruct()
    def deconstruct(self):
        # eth = ['{:02x}'.format(x) for x in struct.unpack(f'!{self.sizes["ETH"]}B',self.raw[:self.sizes["ETH"]])]
        # ipv4 = ['{:02x}'.format(x) for x in struct.unpack(f'!{self.sizes["IPv4"]}B',self.raw[self.sizes["ETH"]:self.sizes["ETH"]+self.sizes["IPv4"]])]
        eth = self.data[:14]
        ipv4 = self.data[14:]
        headers = [{
            'Destination':aob2mac(eth[:6]),
            'Source':aob2mac(eth[6:12]),
            'Type':ethertype(eth[12:])
        }]
        
        return eth,ipv4

# class packet:
#     def __init__(self,raw):
#         self.raw=raw
#         self.type = None
#         self.packet=self.deconstruct()
#     def deconstruct(self):
#         eth = pconfig.load('eth',self.raw[:14])
#         self.type = eth['type']
#         if self.type == 'IPv4':
#             ptype = pconfig.load('ipv4',self.raw[14:34])
#         elif self.type == 'ARP':
#             ptype = pconfig.load('arp',self.raw[14:42])
#         return {'eth':eth,self.type.lower():ptype}


# p=packet(bytearray.fromhex('400d1037bad0f83441f89a0d0800450000288bb2400040064a2ac0a8001668103c25ab0201bb1ba1885e4765ed7150100dbcb7900000'))
# print(p.eth)
# print(p.ipv4)

