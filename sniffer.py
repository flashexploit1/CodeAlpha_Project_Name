from scapy.all import *

interface = 'wlan1mon'
probeReqs = []

def sniffProbes(p):
    if p.haslayer(Dot11ProbeReq):
        netName = p.getlayer(Dot11ProbeReq).info.decode('utf-8')
        if netName not in probeReqs:
            probeReqs.append(netName)
            print(' [+] Detected New Probe Request: ' + netName)

sniff(iface=interface, prn=sniffProbes)
