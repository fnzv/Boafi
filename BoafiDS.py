
#!/usr/bin/python
### Boafi Detecton System to log every packet of the network and keep track of connections 
####### Features: 
#######         -Filter,Redirect,Block traffic
#######         -Souspicious traffic is being blocked and notify via Logs or local DB --> webGUI
#######         -Dump all network traffic into .pcap file 
#######         -This should work independently from wlan0 & eth0 or work as a "bridge" between them

###  Author: Yessou Sami 
###  Project Boafi

import os,time,argparse

parser = argparse.ArgumentParser()


parser.add_argument('-i', action='store', dest='int',
                    help='Interface to log packets')



parser.add_argument('-o', action='store', dest='output',
                    help='Specify filename')


parser.add_argument('-c', action='store', dest='packets',
                    help='Number of packets to log ')


parser.add_argument('-t', action='store_true', default=False,
                    dest='timestamp',
                    help='Insert timestamp in file name?')


parser.add_argument('-mitm', action='store_true', default=False,
                    dest='mitm',
                    help='Enable Man in the Middle module(ARPSPOOF)')



parser.add_argument('-block', action='store_true', default=False,
                    dest='block',
                    help='Enable firewall rules to block traffic') #load rules from external file or via other args
                    



results = parser.parse_args()

mitm=results.mitm
block=results.block
packets=str(results.packets)
int=str(results.int)

if results.output !=" " :
        output_file=str(results.output)+"_"+int
else :
        output_file="DUMP_"+int


ts=output_file+str(time.time()) # timestamp in UTC
os.popen("nohup tcpdump -i "+int+" -c "+packets+" -C 1 -w "+ts+".cap >/dev/null 2>&1 &") ## Log all packets running on eth0 when plugged in



## TODO
##Start firewall 
###Do filtering
###Do redirect
#notify Suspicious traffic passes
#smart detect traffic decide firewall rules (bad dns server queries,bad ip addreses,ban C&C botnet ip addresses..)

##Start mitm 
##dns poison
##arp spoof








