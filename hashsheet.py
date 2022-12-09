import vt
from multiprocessing.pool import ThreadPool, Pool
from multiprocessing import Pool,Manager
from time import sleep
import threading
import csv
from pathlib import Path
import argparse
import math
import numpy as np

def gethashes(params):
    
    scrapedinfo=params[0]
    waittime=params[1]
    keysmap=params[2]
    hash,key=params[3]
    client=get_client(key)
    while key not in keysmap:
        sleep(2)
    try:
        
        keysmap.remove(key)
        data=client.get_object("/files/{}".format(hash))
        scrapedinfo.append([data.md5,data.sha1,data.sha256])
        sleep(waittime)
    except:
        print("Failed to find hash ",hash)
    keysmap.append(key)

def get_client(key):
    threadLocal = threading.local()

    client = getattr(threadLocal, 'client', None)
    if client is None:
        client =vt.Client(key)
        setattr(threadLocal, 'client', client)
    return client

if __name__ == "__main__":
    print ("""
        _   _           _       ____  _               _   
        | | | | __ _ ___| |__   / ___|| |__   ___  ___| |_ 
        | |_| |/ _` / __| '_ \  \___ \| '_ \ / _ \/ _ \ __|
        |  _  | (_| \__ \ | | |  ___) | | | |  __/  __/ |_ 
        |_| |_|\__,_|___/_| |_| |____/|_| |_|\___|\___|\__|

           
           Created by Ebraam Mesak (Bormaa)
           """)
    parser = argparse.ArgumentParser(description='HashSheet is a simple program to get equivelent hashes of same file from VirusTotal into one sheet without duplicates')
    parser.add_argument('keys_file',help='txt file that includes the VirusTotal keys') 
    parser.add_argument('hashes_file',help='csv file that includes the hashes') 

    parser.add_argument('-w','--wait', help='Specify the wait time between requests, free VirusTotal allow only 4 requests per minutes', default=17, required=False)
    parser.add_argument('-p','--premium', help='This option to indicate that your virustotal is premium to set wait time to 0', action='store_true',default=False, required=False)
    parser.add_argument('-o','--output', help='Specify the output name of sheet',default="hashsheet.csv", required=False)
    parser.add_argument('-t','--thread', help='Specify the maximum number of threads', default=5, required=False)

    args = vars(parser.parse_args())
    maxthreads=args["thread"]
    waittime=args["wait"]
    premium=args["premium"]
    output=args["output"]
    keys=[]
    hashes=[]
    if premium:
        waittime=1
    try:
        
        with open(args["hashes_file"], 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                for string in row:
                    if len(string)==32 or len(string)==40 or len(string)==64:
                        hashes.append(string)
        print("Found ",len(hashes)," Hashes")
    except:
        print("Error with reading ",args["hashes_file"])
    try:
        
        fkeys = open(args["keys_file"], "r")
        for x in fkeys:
            keys.append(x.strip())
    except:
        print("Error with reading ",args["keys_file"])

    manager = Manager()
    global scrapedinfo
    scrapedinfo = manager.list()
    scrapedinfo.append(["MD5","SHA-1","SHA-256"])
    global keysmap
    keysmap = manager.list()
    for key in keys:
        keysmap.append(key)
    listwithkey=[]
    refkey=0
    for hash in hashes:
        refkey=refkey%len(keys)
        listwithkey.append([hash,keys[refkey]])
        refkey=refkey+1
    p = Pool(min(len(hashes),maxthreads,math.floor(60/waittime)))
    
    p.map(gethashes, list((scrapedinfo,waittime,keysmap, param) for param in listwithkey))
    p.terminate()
    p.join()
    md5unique=[]
    outputlist=[]
    for i in scrapedinfo:
        md5=i[0]
        if md5 not in md5unique:
            outputlist.append(i)
            md5unique.append(md5)
    
    np.savetxt(output, outputlist, delimiter=',', fmt='%s')
    print("Output file is ",output)
