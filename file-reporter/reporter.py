import os
import sys
import pefile
import hashlib
import re

FILE=sys.argv[1]

pe=pefile.PE(name=FILE,fast_load=False)

def file_hash(hash='md5'):
    if hash=='md5':
        hash=hashlib.md5()
    elif hash=='sha1':
        hash=hashlib.sha1()
    with open(FILE,'rb') as f:
        b = f.read()
        hash.update(b)
    return hash.hexdigest()

def compile_strings():
    with open(FILE,'rb') as f:
        b=f.read()
    strs=re.findall(rb'\w{3,}',b)
    strs=[x.decode() for x in strs]
    return strs

def find_ips(strs):
    return re.findall(r'''
\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b''','\n'.join(strs))

def find_domains(strs):
    return re.findall(r'''
    .+\.(co\.uk|uk|com|co|app|net|org|org\.uk|io|eu|
        ac|af|ag|ai|am|as|at|xyz|yt|us|tv|tk|tl|to|vc
        |tw|sx|tc|se|sc|sg|sh|rip|pt|qa|pm|pl|re|nz|nl
        |nu|mx|lol|la|lt|it|je|is|jp|id|im|in|gg|fr|fm
        |fail|es|dev|cz|cx|cc|bz)''','\n'.join(strs))

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
    filename=f'{os.path.splitext(FILE)[0]}_report'
    if not os.path.exists(filename):
        os.mkdir(filename)
    with open(f'{filename}/{filename}.txt','w') as f:
        f.write(data)
    with open(f'{filename}/strings.txt','w') as f:
        f.write('\n'.join(compile_strings()))

def prepare_data():
    data=[FILE.upper(),'='*50]
    headers=parse_headers()
    data.append(f'MD5: {file_hash()}')
    data.append(f'SHA1: {file_hash(hash="sha1")}')
    data.append('='*50)
    for h in headers:
        data.append(f'{h}: {hex(headers[h])}')
    data.append('='*50)
    data.append('A full list of strings can be found in the file "strings.txt"\n')
    strs=compile_strings()
    data.append('\n'.join(find_ips(strs)))
    data.append('\n'.join(find_domains(strs)))
    data.append('='*50)
    write_report('\n'.join(data))

if __name__ == '__main__':
    prepare_data()

# Machine: 
# NumberOfSections:
# Magic:
# AddressOfEntryPoint:
# Subsystem:
# DllCharacterisitcs: 
#
# Find suspicious strings: IPs and C2 domains
# Check for suspicious imports