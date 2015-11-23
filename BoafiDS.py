
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


parser.add_argument('--auto', action='store_true', default=False,
                    dest='sdsAuto',
                    help='Auto-SDS')



parser.add_argument('--admin', action='store', dest='adminIP', default="none", help='Specify only ip allowed or subnet network for Admin rights')


parser.add_argument('--allowNet', action='store', dest='allowedNet', default="none", help='Specify only ip allowed or subnet network for allowed network')



parser.add_argument('--ena', action='store', dest='ena',
                    help='Enable active  SDS activity..  packet flow monitoring')




results = parser.parse_args()


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
        ##Every 500k packets a new file is wrote
        ts=output_file+str(time.time()) # timestamp in UTC
        os.popen("nohup tcpdump -i "+int+" -c "+packets+" -C 1 -w "+ts+".cap >/dev/null 2>&1 &") ## Log all packets running on eth0 when plugged in



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
                #Start an activity logger and every minute updates and checks\learn new rules
                if(results.ena):
                        print "Start active sds"
                        ##Every 100 packets a new file is wrote and
                        ts=output_file+str(time.time()) # timestamp in UTC
                        os.popen("nohup tcpdump -i "+int+" -c 100 -C 1 -w "+ts+".cap >/dev/null 2>&1 &") ## Log all packet$


                else: #Doesn't start activity logger
                        print "passive sds"
                        #URLSNARF check sites and block strange activity
                        # OR TCPDUMP and then DPKT to parse packets
                        #https://github.com/ameygat/pyscripts/blob/master/pcap_public.py
                        #https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
                        #Dynamic iptable rules
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





