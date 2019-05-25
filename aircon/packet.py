import pconfig

# ETH_SIZE = 14
# IPV4_SIZE = 20

# def aob2ip(bytes):
#     return '.'.join([str(int(x,base=16)) for x in bytes])

# def aob2mac(bytes):
#     return ':'.join(bytes)

# def aob2int(bytes):
#     return int(aob2str(bytes),base=16)

# def aob2str(bytes):
#     return ''.join(bytes)

# def aob2hex(bytes):
#     return f'0x{aob2str(bytes)}'

# def ethertype(bytes):
#     bytes=aob2str(bytes)
#     types={
#         '0800':'IPv4',
#         '0806':'ARP',
#         '86dd':'IPv6'
#     }
#     return types.get(bytes,bytes)

# def protocols(b):
#     types={
#         '06':'TCP',
#         '11':'UDP',
#         '01':'ICMP'
#     }
#     return types.get(b,aob2hex(b))

# class packet:
#     def __init__(self,raw):
#         self.raw=raw
#         self.eth={}
#         self.ipv4={}
#         self.packet=self.deconstruct()
#     def deconstruct(self):
#         eth = ['{:02x}'.format(x) for x in struct.unpack(f'!{ETH_SIZE}B',self.raw[:ETH_SIZE])]
#         ipv4 = ['{:02x}'.format(x) for x in struct.unpack(f'!{IPV4_SIZE}B',self.raw[ETH_SIZE:ETH_SIZE+IPV4_SIZE])]
#         self.eth = {
#             'Destination':aob2mac(eth[:6]),
#             'Source':aob2mac(eth[6:12]),
#             'Type':ethertype(eth[12:])
#         }
#         self.ipv4 = {
#             'Version':aob2int(ipv4[0][0]),
#             'Header length':aob2int(ipv4[0][1])*4,
#             'Differentiated Services Field':aob2hex(ipv4[1]),
#             'Total Length':aob2int(ipv4[2:4]),
#             'Identification':aob2hex(ipv4[4:6]),
#             'Flags':aob2hex(ipv4[6:8]),
#             'Time to live':aob2int(ipv4[8]),
#             'Protocol':protocols(ipv4[9]),
#             'Header checksum':aob2hex(ipv4[10:12]),
#             'Source':aob2ip(ipv4[12:16]),
#             'Destination':aob2ip(ipv4[16:])
#         }

class packet:
    def __init__(self,raw):
        self.raw=raw
        self.type = None
        self.packet=self.deconstruct()
    def deconstruct(self):
        eth = pconfig.load('eth',self.raw[:14])
        self.type = eth['type']
        if self.type == 'IPv4':
            ptype = pconfig.load('ipv4',self.raw[14:34])
        elif self.type == 'ARP':
            ptype = pconfig.load('arp',self.raw[14:42])
        return {'eth':eth,self.type.lower():ptype}


# p=packet(bytearray.fromhex('400d1037bad0f83441f89a0d0800450000288bb2400040064a2ac0a8001668103c25ab0201bb1ba1885e4765ed7150100dbcb7900000'))
# print(p.eth)
# print(p.ipv4)

