import os
import sys
import time
import hashlib
import psutil
import threading

def dcache(dir):
    cache=[]
    for i in os.listdir(dir):
        c=f'{dir}\\{i}'
        payload='.'*os.path.getsize(c)
        with open(c,'w') as f:
            f.write(payload)
        hash=hashlib.md5(str(time.time()).encode()).hexdigest()
        while os.path.isfile(f'{dir}\\{hash}'):
            hash=hashlib.md5(str(time.time()).encode()).hexdigest()
        os.rename(c,f'{dir}\\{hash}')
        cache.append(f'{dir}\\{hash}')
    for c in cache:
        os.remove(c)

def kproc(name):
    processes=[]
    for pid in psutil.pids():
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            if proc.name() == name:
                pname=proc.exe()
                if not pname in processes:
                    processes.append(pname)
                proc.kill()
    return processes

def rproc(procs):
    for p in procs:
        t = threading.Thread(target=os.system,args=(p,),name='runProc')
        t.daemon = True
        t.start()

if __name__ == '__main__':
    procs=kproc('Discord.exe')
    print(procs)
    cachedir=[os.getenv('APPDATA')+r'\discord\Cache',os.getenv('APPDATA')+r'\discord\GPUCache']
    for dir in cachedir:
        t = threading.Thread(target=dcache,args=(dir,),name='delCache')
        t.daemon = True
        t.start()
    rproc(procs)
    time.sleep(2)
    os._exit(1)