#!/usr/bin/python

#####  BoafiGate.py
###  - Start TOR service
##   - Dependencies : tor,iptables
#    - Transparent tunnel via iptables to force all traffic go on TOR network 
#    - Every user connected via wifi or ethernet to boafi can access internet only via TOR if enabled
####
## EXAMPLE:  ./boafiGate.py -loadcfg -ip 192.168.42.1 -run
## runs Tor on 192.168.42.1:9040 as a transparent proxy and loads iptables rules to redirect all traffic on the proxy


###  Author: Yessou Sami 
###  Project Boafi
###  Working with /Configurations/tor/torrc and iptables rules


import os,time,argparse
##Be Sure to use the right configuration for Transparent Proxy(port 9040)

parser = argparse.ArgumentParser()


parser.add_argument('-loadcfg', action='store_true', dest='loadcfg',
                    help='Load the default torrc settings of the system and start the tor service')
                    
parser.add_argument('-loadrules', action='store_true', dest='loadrules',
                    help='Load iptables rules')
    
parser.add_argument('-proxy', action='store', dest='loadproxy',default="none",
                    help='Load transparent proxy rules to given address')

parser.add_argument('-stop', action='store_true', dest='stop',
                    help='Stop TOR and restore Iptables')


parser.add_argument('-run', action='store_true', dest='run',
                    help='Run\Restart Tor service')

parser.add_argument('-ip', action='store', dest='ip',
                    help='Specify the ip address of the Boafi interface that will serve as Tor Gateway ')








results = parser.parse_args()

loadcfg=results.loadcfg

if (results.ip):
        ip=str(results.ip)
else:
        ip="192.168.42.1"








## Use this configuration when the raspberry is the default gateway ---> (Wlan Hostpod)       
torrc="""
Log notice file /var/log/tor/notices.log
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsSuffixes .onion,.exit
AutomapHostsOnResolve 1
TransPort 9040
TransListenAddress """+ip+""" 
DNSPort 53
DNSListenAddress """+ip






if(results.loadcfg):

        if("tor" in os.popen("ps -A | grep 'tor'").read()):
                print "TOR is working"
               
                if not (os.popen("cat /etc/tor/torrc").read() in torrc):
                  os.popen("echo '"+torrc+"' > /etc/tor/torcc")
                  print "Moving configuration to /etc/tor/torrc"
                ## Run iptables rules in ram and don't store them
                # except traffic 22,53
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 22 -j REDIRECT --to-ports 22") 
                #Rule to allow us to ssh in rpi 
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-ports 53") 
                #Rule to allow dns requests
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --syn -j REDIRECT --to-ports 9040") 
        else:
                print "Starting TOR service"
                os.popen("service tor stop")## check
                os.popen("service tor start")
                #check configuration

if(results.loadrules):
         ## Run iptables rules in ram and don't store them
                # except traffic 22,53
                print "Added Transparent TOR Proxy Rules!"
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 22 -j REDIRECT --to-ports 22") 
                #Rule to allow us to ssh in rpi 
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-ports 53") 
                #Rule to allow dns requests
                os.popen("sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --syn -j REDIRECT --to-ports 9040") 

if(results.run):
                print "Starting TOR service"
                os.popen("service tor stop")
                os.popen("service tor start")

if(results.stop):
                os.popen("sudo service tor stop")
                print "Stoppend TOR service"
                os.popen("sudo iptables -F")
                os.popen("sudo iptables -X")
                os.popen("sudo iptables-restore < /etc/iptables.ipv4.nat")
                print "Restored Default iptables rules from /etc/iptables.ipv4.nat"
                
if not(results.loadproxy=="none"): ## ONLY HTTP & HTTPS
                # Proxy should be (socket format or just ip)  example 192.168.1.1:3128 or 1.1.1.1 
                #can be an external proxy or local
                proxy=results.loadproxy
                os.popen("iptables -t nat -A PREROUTING -m multiport -p tcp --dports 80,443 -j DNAT --to "+proxy)
                os.popen("iptables -t nat -I FORWARD -d "+proxy+" -j ACCEPT")
## Traffic generated from the machine its self won't be run on the proxy
                print "Added Proxy rules!"
                
                
                
##### TODO:
####  Add iptables rules to force all traffic except ssh and dns for management
###   Add torrc configuration file checker
##    Add install module to install tor via simple command and configure it with the script.. 
#     Add external support for Bridge/Exit Relay... and other rules 
#     Add Alternative VPN\proxy if tor fails
# example : ./boafiGate.py -install -ip 192.168.42.1 -loadall lan
  
