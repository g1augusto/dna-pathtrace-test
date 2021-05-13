from dnalibrary import DnaC
import json
from random import seed,randint

credentials = {"username":"devnetuser","password":"Cisco123!"}
dna = DnaC("sandboxdnac.cisco.com")
dna.connect(**credentials)
hostlist = dna.hostlist()
devicelist = dna.devicelist()
iplist = []
for host in hostlist:
    iplist.append(host["hostIp"])
for device in devicelist:
    iplist.append(device["managementIpAddress"])
iplist.append("8.8.8.8")
iplist.append("9.9.9.9")
src = ""
dst = ""
while (src == dst) or (src == "") or (dst == ""):
    random = randint(0,len(iplist)-1)
    src = iplist[random]
    random = randint(0,len(iplist)-1)
    dst = iplist[random]
    print(f"src: {src}    dst: {dst}")
dna.pathtrace(src,dst)
