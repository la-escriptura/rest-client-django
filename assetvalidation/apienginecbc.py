import requests
import json
import csv
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

class ApiEngineCbc():
    cbcFlds = [["name",0], ["lastInternalIpAddress",1], ["lastContactTime",2], ["status",3], ["registeredTime",4], ["policyName",5], ["sensorVersion",6]]
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
        for cbcFld in range(len(self.cbcFlds)): 
            head.append(self.cbcFlds[cbcFld][0])
        head.append('organization')
        return head

    def cbcConsole(self, key, token, org):
        url = "https://defense-prod05.conferdeploy.net/appservices/v6/orgs/" + key + "/devices/_search/download?status=ALL"
        payload = {}
        header = {"X-Auth-Token":token, "content-type":"application/json"}
        b9StrongCert = False
        r = requests.get(url, json.dumps(payload), headers=header, verify=b9StrongCert)
        r.raise_for_status()
        receive = r.content.decode('utf-8')
        data = list(csv.reader(receive.splitlines(), delimiter=','))
        cbcCols = data[0:1][0]
        for cbcFld in range(len(self.cbcFlds)): 
            for cbcCol in range(len(cbcCols)): 
                if (self.cbcFlds[cbcFld][0] == cbcCols[cbcCol]): 
                    self.cbcFlds[cbcFld][1] = cbcCol; 
                    break;
        cbcHost = {}
        cbcIP = {}
        cbcTbl = {}
        items = data[1:]
        for i in range(len(items)): 
            body = []
            for cbcFld in range(len(self.cbcFlds)): 
                body.append(items[i][self.cbcFlds[cbcFld][1]])
            body.append(org)
            cbcHost[self.GetHost(self.GetHost(items[i][self.cbcFlds[0][1]],".",0),"\\",1).lower()] = key + str(i)
            cbcIP[items[i][self.cbcFlds[1][1]]] = key + str(i)
            cbcTbl[key + str(i)] = body
        return cbcHost, cbcIP, cbcTbl
    
    def validatecbc(self, hostnames=None, ipaddresses=None):
        tblCBCloud = ({},{},{})
        if (not ((hostnames is None) and (ipaddresses is None))):
            cbcorgs = []
            threads = [None] * len(cbcorgs)
            for th in range(len(threads)):
                key = cbcorgs[th][0:8]
                token = cbcorgs[th][8:43]
                org = cbcorgs[th][43:]
                threads[th] = ThreadWithReturnValue(target=self.cbcConsole, args=(key,token,org,))
                threads[th].start()
            for th in range(len(threads)):    
                tbl = threads[th].join()
                tblCBCloud = tblCBCloud[0] | tbl[0] , tblCBCloud[1] | tbl[1] , tblCBCloud[2] | tbl[2]
            
        assetvalidation = []
        if (hostnames is not None):
            hosts = []
            for hostname in hostnames.splitlines():
                hosts += hostname.strip().split()
            for host in range(len(hosts)): 
                barehost = self.GetHost(self.GetHost(hosts[host],".",0),"\\",1).lower()
                if (not ((barehost not in tblCBCloud[0]) or (tblCBCloud[0][barehost] is None))): 
                    assetvalidation.append(tblCBCloud[2][tblCBCloud[0][barehost]])
                else:
                    assetvalidation.append([hosts[host],'','','','','','',''])
        
        if (ipaddresses is not None):
            ips = []
            for ipaddress in ipaddresses.splitlines():
                ips += ipaddress.strip().split()
            for ip in range(len(ips)): 
                if (not ((ips[ip] not in tblCBCloud[1]) or (tblCBCloud[1][ips[ip]] is None))): 
                    assetvalidation.append(tblCBCloud[2][tblCBCloud[1][ips[ip]]])
                else:
                    assetvalidation.append(['',ips[ip],'','','','','',''])
        
        return { "assetvalidation": assetvalidation }        
