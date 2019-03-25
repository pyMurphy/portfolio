import os
import time
import hashlib
import psutil

DIR=os.getenv('APPDATA')+r'\discord\Cache'

def killdiscord():
    for pid in psutil.pids():
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            if proc.name() == "Discord.exe":
                proc.kill()

def ocache():
    cache=[]
    for i in os.listdir(DIR):
        c=f'{DIR}\\{i}'
        payload='.'*os.path.getsize(c)
        with open(c,'w') as f:
            f.write(payload)
        hash=hashlib.md5(str(time.time()).encode()).hexdigest()
        while os.path.isfile(f'{DIR}\\{hash}'):
            hash=hashlib.md5(str(time.time()).encode()).hexdigest()
        os.rename(c,f'{DIR}\\{hash}')
        cache.append(f'{DIR}\\{hash}')
    return cache

def dcache(cache):
    for c in cache:
        os.remove(c)

if __name__ == '__main__':
    killdiscord()
    dcache(ocache())