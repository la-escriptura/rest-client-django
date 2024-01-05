import requests
import json
import csv
import math
from threading import Thread

class ThreadWithReturnValue(Thread):
    #Keyword Arguments
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)
    def join(self, *args):
        Thread.join(self, *args)
        return self._return

class ApiEngineCbp():
    cbpFlds = ["name", "ipAddress", "lastPollDate", "connected", "isActive", "dateCreated", "policyName", "agentVersion", "osShortName"]
    verify = False
    if (not verify):
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def GetHost(self, fqdn, delimiter, index):
        hostname = fqdn.split(delimiter)
        if len(hostname) > 1:
            return hostname[index]
        else:
            return hostname[0]
        
    def GetHeader(self):
        head = []
        for cbpFld in range(len(self.cbpFlds)): 
            head.append(self.cbpFlds[cbpFld])
        head.append('instance')
        return head
        
    def cbpPage(self, fqdn, token, limit, offset):
        url = "https://" + fqdn + ":443/api/bit9platform/v1/computer?sort=ipAddress&offset="+str(offset)+"&limit="+str(limit)
        payload = {}
        header = {"X-Auth-Token":token, "content-type":"application/json"}
        b9StrongCert = False
        r = requests.get(url, json.dumps(payload), headers=header, verify=b9StrongCert)
        r.raise_for_status()
        receive = r.json()
        server = self.GetHost(fqdn,".",0)
        cbpHost = {}
        cbpIP = {}
        cbpTbl = {}
        i = 0
        l = len(receive)
        while (i < l):
            hostname = "" if ((self.cbpFlds[0] not in receive[i]) or (receive[i][self.cbpFlds[0]] is None)) else receive[i][self.cbpFlds[0]]
            ipaddress = "" if ((self.cbpFlds[1] not in receive[i]) or (receive[i][self.cbpFlds[1]] is None)) else receive[i][self.cbpFlds[1]]
            barehost = self.GetHost(self.GetHost(hostname,".",0),"\\",1).lower()
            if (not((barehost in cbpHost) and (ipaddress in cbpIP))):
                body = [hostname,ipaddress]
                cbpFlds = self.cbpFlds[2:]
                for cbpFld in range(len(cbpFlds)): 
                    body.append("" if ((cbpFlds[cbpFld] not in receive[i]) or (receive[i][cbpFlds[cbpFld]] is None)) else str(receive[i][cbpFlds[cbpFld]]))
                body.append(fqdn)
                cbpHost[barehost] = server + str(offset + i)
                cbpIP[ipaddress] = server + str(offset + i)
                cbpTbl[server + str(offset + i)] = body
            i = i + 1
        return cbpHost, cbpIP, cbpTbl

    def cbpConsole(self, fqdn, token):
        url = "https://" + fqdn + ":443/api/bit9platform/v1/computer?limit=-1"
        payload = {}
        header = {"X-Auth-Token":token, "content-type":"application/json"}
        b9StrongCert = False
        r = requests.get(url, json.dumps(payload), headers=header, verify=b9StrongCert)
        r.raise_for_status()
        receive = r.json()
        limit = 1000
        offset = 0
        pageThreads = [None] * math.ceil(receive["count"]/limit)
        for thP in range(len(pageThreads)):
            pageThreads[thP] = ThreadWithReturnValue(target=self.cbpPage, args=(fqdn,token,limit,offset,))
            pageThreads[thP].start()
            offset = offset + limit
        tblInstance = ({},{},{})
        for thP in range(len(pageThreads)):    
            tblP = pageThreads[thP].join()
            tblInstance = tblInstance[0] | tblP[0] , tblInstance[1] | tblP[1] , tblInstance[2] | tblP[2]
        return tblInstance
    
    def validatecbp(self, hostnames=None, ipaddresses=None):
        tblCBProtect = ({},{},{})
        if (not ((hostnames is None) and (ipaddresses is None))):
            cbpinstances = []
            consoleThreads = [None] * len(cbpinstances)
            for thC in range(len(consoleThreads)):
                token = cbpinstances[thC][0:36]
                fqdn = cbpinstances[thC][36:]
                consoleThreads[thC] = ThreadWithReturnValue(target=self.cbpConsole, args=(fqdn,token,))
                consoleThreads[thC].start()
            for thC in range(len(consoleThreads)):    
                tblC = consoleThreads[thC].join()
                tblCBProtect = tblCBProtect[0] | tblC[0] , tblCBProtect[1] | tblC[1] , tblCBProtect[2] | tblC[2]
            
        assetvalidation = []
        if (hostnames is not None):
            hosts = []
            for hostname in hostnames.splitlines():
                hosts += hostname.strip().split()
            for host in range(len(hosts)): 
                barehost = self.GetHost(self.GetHost(hosts[host],".",0),"\\",1).lower()
                if (not ((barehost not in tblCBProtect[0]) or (tblCBProtect[0][barehost] is None))): 
                    assetvalidation.append(tblCBProtect[2][tblCBProtect[0][barehost]])
                else:
                    assetvalidation.append([hosts[host],'','','','','','','','',''])
        
        if (ipaddresses is not None):
            ips = []
            for ipaddress in ipaddresses.splitlines():
                ips += ipaddress.strip().split()
            for ip in range(len(ips)): 
                if (not ((ips[ip] not in tblCBProtect[1]) or (tblCBProtect[1][ips[ip]] is None))): 
                    assetvalidation.append(tblCBProtect[2][tblCBProtect[1][ips[ip]]])
                else:
                    assetvalidation.append(['',ips[ip],'','','','','','','',''])
        
        return { "assetvalidation": assetvalidation }        
