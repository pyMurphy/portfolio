import struct

class packet:
    def __init__(self,raw):
        self.raw = raw
        self.content=['{:02x}'.format(x) for x in struct.unpack(f'!{len(self.raw)}B',self.raw)]