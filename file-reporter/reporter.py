import os
import sys
import pefile
import hashlib

FILE=sys.argv[1]

pe=pefile.PE(name=FILE,fast_load=False)

def file_hash():
    hash=hashlib.md5()
    with open(FILE,'rb') as f:
        b = f.read()
        hash.update(b)
    return hash.hexdigest()

def parse_headers():
    opt_header=pe.OPTIONAL_HEADER.dump_dict()
    dos_header=pe.DOS_HEADER.dump_dict()
    file_header=pe.FILE_HEADER.dump_dict()
    data = {
        'Machine':file_header['Machine']['Value'],
        'Magic':dos_header['e_magic']['Value'],
        'Subsystem':opt_header['Subsystem']['Value'],
        'NumberOfSections':file_header['NumberOfSections']['Value'],
        'DllCharacteristics':opt_header['DllCharacteristics']['Value'],
        'AddressOfEntryPoint':opt_header['AddressOfEntryPoint']['Value']
    }
    return data

def write_report(data):
    with open(f'{os.path.splitext(FILE)[0]}_report.txt','w') as f:
        f.write(data)

data=[]
headers=parse_headers()
data.append(f'Hash: {file_hash()}')
for h in headers:
    data.append(f'{h}: {hex(headers[h])}')

write_report('\n'.join(data))