
#!/usr/bin/python
### Boafi Detecton System to log every packet of the network and keep track of connections 
####### Features: 
#######         -Filter,Redirect,Block traffic
#######         -Souspicious traffic is being blocked and notify via Logs or local DB --> webGUI
#######         -Dump all network traffic into .pcap file 
#######         -This should work independently from wlan0 & eth0 or work as a "bridge" between them

###  Author: Yessou Sami 
###  Project Boafi
#!/usr/bin/python

import os,time,argparse

parser = argparse.ArgumentParser()


parser.add_argument('-i', action='store', dest='int', default="wlan0",
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


parser.add_argument('--auto', action='store_true', default=False,
                    dest='sdsAuto',
                    help='Auto-SDS')



parser.add_argument('--admin', action='store', dest='adminIP', default="none", help='Specify only ip allowed or subnet network for Admin rights')


parser.add_argument('--allowNet', action='store', dest='allowedNet', default="none", help='Specify only ip allowed or subnet network for allowed network')



parser.add_argument('--ena', action='store_true', dest='ena',
                    help='Scan Packet Capture log and automatically create rules')


parser.add_argument('--spoof', action='store_true', dest='arpspoof',
                    help='Enable arp spoofing to apply firewall rules on eth0')


parser.add_argument('--dg', action='store', dest='dgIP', default="192.168.1.1", help='Specify the ip address of the default gateway to spoof ')






allowedNet=results.allowedNet
adminIP=results.adminIP
sdsAuto=results.sdsAuto
sds=results.sds
packets=str(results.packets)
int=str(results.int)
print "RUNNING"
if results.output !=" " :
        output_file=str(results.output)+"_"+int
else :
        output_file="DUMP_"+int


print "pre log"
if(results.log):
        ts=output_file+str(time.time()) # timestamp in UTC
        os.popen("nohup tcpdump -i "+int+" -c "+packets+" -C 1 -w "+ts+".cap >/dev/null 2>&1 &") ## Log all packets running on eth0 when plugged in
        # FORCE GATEWAY? arpspoof -i eth0  -t iptarget ipgateway


print "postlog"
##Start firewall if args are true
###Do filtering
###Do redirect
if(sds): #start SDS
        print "Starting SDS"
        if(results.sdsAuto):
                print "SDS AUTO"
        #Allow SSH Remote connection only to admin device IP
                if not(adminIP == "none"):
                        print "Securing admin ip"
                        os.popen("iptables -A INPUT -s "+adminIP+" -p tcp --dport 22 -j ACCEPT")
                        os.popen("iptables -A INPUT -s "+adminIP+" -p tcp --match multiport --dports 80,443,53 -j ACCEPT")
                        os.popen("iptables -A INPUT -s "+adminIP+" -p udp --match multiport --dports 80,443,53 -j ACCEPT")
                        os.popen("iptables -P INPUT DROP")
                else:
                        print "no admin?"
                        #os.popen("iptables -P INPUT DROP")
                if not(allowedNet == "none"):
        #Limit Network Access only to allowedNet  (port range 1-1024 tcp/udp)
                        print "Securing net allowed"
                        os.popen("iptables -I FORWARD -s "+allowedNet+" -j ACCEPT")
                        os.popen("iptables -I FORWARD -s "+allowedNet+" -p tcp --match multiport  --dports 1:1024 -j ACCEPT")
                        os.popen("iptables -I FORWARD -s "+allowedNet+" -p udp --match multiport  --dports 1:1024 -j ACCEPT")
                        os.popen("iptables -P FORWARD DROP")
                os.system('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all') #Ignore Pings to the machine
                os.system('echo "1" > /proc/sys/net/ipv4/tcp_syncookies') #SYN Flood Protection
                os.system('echo "123" > /proc/sys/net/ipv4/ip_default_ttl') #Hide TTL Value
                print "Secured SYN Flood and Ping attacks"
                #Start an activity logger and create new rules
                if(results.ena):
                        #use pcap and block
                        print "ena"

                else: #Doesn't start activity logger but uses a static iptables firewall loaded from local or (download from net?) Blocked url list
                        f=open("SDSlist","r") #Open external file to see what sites can pass our gateway
                        filterlist=f.read()  # list based on keywords
                        for line in filterlist.split(): #Apply URL Filterbased firewall
                                os.popen("iptables -I FORWARD -p tcp --match multiport --dports 80,443 -m string "+line)
                                print "added: ",line




                # Run tcpdump get some packets and decide from these what are bad packets.. D(inamic)IPtables

        #If not auto Start Manual SDS with single rules activation
        else:
                print "Start Manual sds"
                        #Read values from ARGS and send them directly to iptables
                        #Static IP tables rules...






######TODO
#### sds--auto 
## Add Sticky MAC Filtering?
## Add Basic url filtering 
## Add Logging feature for traffic on dns,http
## Add Learning feature to block new suspicious traffic.. (EXAMPLE : if network requests are the same during a long periond learn
#                                                            and adapt the network to these... elif other new requests are denied..)
## Saving firewall config via iptables-save and -sds--load to load a new configuration
## Add Banned ip list | banned url list | banned mac list | 
## Add function to allow network access only to Registered users on Captive Portal





