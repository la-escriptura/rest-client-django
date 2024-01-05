import requests
import json
import csv
import xml.etree.ElementTree as ET
import subprocess
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

class ApiEngineTw():
    twFlds = ["name","inUseIpAddress","ipAddresses","licenses","model","axonAgent","teAgent"]
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
        for twFld in range(len(self.twFlds)): 
            head.append(self.twFlds[twFld])
        head.append('instance')
        return head

    def twConsole(self, fqdn, usr, pwd):
        xml = subprocess.run(["D:\\Utilities\\twtool86\\bin\\twtool.cmd","report","-T","Tripwire Agents","-F","XML","-s","https://" + fqdn + "/twservice/soap","-u",usr,"-p",pwd,"-Q"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, check=True, encoding="utf-8").stdout
        root = ET.fromstring(xml)
        server = self.GetHost(fqdn,".",0)
        twHost = {}
        twIP = {}
        twTbl = {}
        i = 0
        for child in root.findall("ReportBody/ReportSection[@category='node']"):
            hostname = "" if (child.get(self.twFlds[0]) is None) else child.get(self.twFlds[0])
            barehost = self.GetHost(self.GetHost(hostname,".",0),"\\",1).lower()
            ipaddress = []
            if (child.find("String[@name='"+self.twFlds[1]+"']").text is not None):
                inUseIpAddress = child.find("String[@name='"+self.twFlds[1]+"']").text
                ipaddress.append(inUseIpAddress)
            else:
                inUseIpAddress = ""
            if (child.find("String[@name='"+self.twFlds[2]+"']").text is not None):
                ipAddresses = child.find("String[@name='"+self.twFlds[2]+"']").text
                ipaddress += ipAddresses.split(", ")
            else:
                ipAddresses = ""
            isExist = False
            for ipadd in range(len(ipaddress)):
                if (ipaddress[ipadd] in twIP):
                    isExist = True
                    break;
            if (not(isExist and (barehost in twHost))):
                body = [hostname,inUseIpAddress,ipAddresses]
                twFlds = self.twFlds[3:]
                for twFld in range(len(twFlds)): 
                    body.append("" if (child.find("String[@name='"+twFlds[twFld]+"']").text is None) else child.find("String[@name='"+twFlds[twFld]+"']").text)
                body.append(fqdn)
                twHost[barehost] = server + str(i)
                for ipadd in range(len(ipaddress)):
                    twIP[ipaddress[ipadd]] = server + str(i)
                twTbl[server + str(i)] = body
            i = i + 1
        return twHost, twIP, twTbl
    
    def validatetw(self, hostnames=None, ipaddresses=None):
        tblTW = ({},{},{})
        if (not ((hostnames is None) and (ipaddresses is None))):
            twinstances = [[]]
            threads = [None] * len(twinstances)
            for th in range(len(threads)):
                fqdn = twinstances[th][0]
                usr = twinstances[th][1]
                pwd = twinstances[th][2]
                threads[th] = ThreadWithReturnValue(target=self.twConsole, args=(fqdn,usr,pwd,))
                threads[th].start()
            for th in range(len(threads)):    
                tbl = threads[th].join()
                tblTW = tblTW[0] | tbl[0] , tblTW[1] | tbl[1] , tblTW[2] | tbl[2]
            
        assetvalidation = []
        if (hostnames is not None):
            hosts = []
            for hostname in hostnames.splitlines():
                hosts += hostname.strip().split()
            for host in range(len(hosts)): 
                barehost = self.GetHost(self.GetHost(hosts[host],".",0),"\\",1).lower()
                if (not ((barehost not in tblTW[0]) or (tblTW[0][barehost] is None))): 
                    assetvalidation.append(tblTW[2][tblTW[0][barehost]])
                else:
                    assetvalidation.append([hosts[host],'','','','','','',''])
        
        if (ipaddresses is not None):
            ips = []
            for ipaddress in ipaddresses.splitlines():
                ips += ipaddress.strip().split()
            for ip in range(len(ips)): 
                if (not ((ips[ip] not in tblTW[1]) or (tblTW[1][ips[ip]] is None))): 
                    assetvalidation.append(tblTW[2][tblTW[1][ips[ip]]])
                else:
                    assetvalidation.append(['',ips[ip],'','','','','',''])
        
        return { "assetvalidation": assetvalidation }        
