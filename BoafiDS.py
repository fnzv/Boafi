
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


parser.add_argument('-log', action='store_true', default=False,
                    dest='log',
                    help='Enable logging on interface -i')



parser.add_argument('-sds', action='store_true', default=False,
                    dest='sds',
                    help='Enable Smart Detection System')


parser.add_argument('-sds--auto', action='store_true', default=False,
                    dest='sdsAuto',
                    help='Auto-SDS')



parser.add_argument('-sds--admin', action='store', dest='adminIP',
                    help='Specify only ip allowed or subnet network')



results = parser.parse_args()


adminIP=results.adminIP
log=results.log
sds=results.sds
sdsAuto=results.sdsAuto
packets=str(results.packets)
int=str(results.int)

if results.output !=" " :
        output_file=str(results.output)+"_"+int
else :
        output_file="DUMP_"+int



if(log):
        ##Every 500k packets a new file is wrote
        ts=output_file+str(time.time()) # timestamp in UTC
        os.popen("nohup tcpdump -i "+int+" -c "+packets+" -C 1 -w "+ts+".cap >/dev/null 2>&1 &") ## Log all packets running on eth0 when plugged in




##Start firewall if args are true
###Do filtering
###Do redirect
if(sds): #start SDS
        if(sdsAuto):
        #Allow SSH Remote connection only to admin device IP
                os.popen("iptables -I INPUT -s "+adminIP+" -p tcp --dport 22 -j ACCEPT")
                os.popen("iptables -I INPUT -s 0.0.0.0/0 -p tcp --dport 22 -j DROP")
        ##ADD other rules 









