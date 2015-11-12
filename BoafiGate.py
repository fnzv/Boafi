#!/usr/bin/python

#####  BoafiGate.py
###  - Start TOR service
##   - Dependencies : tor,iptables
#    - Transparent tunnel via iptables to force all traffic go on TOR network 
#    - Every user connected via wifi or ethernet to boafi can access internet only via TOR if enabled


###  Author: Yessou Sami 
###  Project Boafi
###  (Under development no test yet)


import os,time,argparse
##ARGS when executed choose for ip addresss

parser = argparse.ArgumentParser()



parser.add_argument('-ip', action='store', dest='ip',
                    help='Specify the ip address of the Boafi interface that will serve as Tor Gateway ')



parser.add_argument('-lan', action='store_true', default=False,
                    dest='lan',
                    help='Allow only LAN ip addresses to connect to this Tor Gateway ')

parser.add_argument('-install', action='store_true', default=False,
                    dest='setup',
                    help='Install tor ')


parser.add_argument('-loadall', action='store_true', default=False,
                    dest='loadall',
                    help='Start All the services and uses the ip address as Tor Gateway')





results = parser.parse_args()

lan=results.lan


ip=results.ip

torrc="""SocksPort 9050
SocksPort """+ip+""":9100
SocksPolicy accept 192.168.1.0/24
SocksPolicy accept 127.0.0.0/8
SocksPolicy reject *
ORPort 9001
Nickname BoafiTor
RelayBandwidthRate 200 KB
RelayBandwidthBurst 400 KB
DirPort 9030
ExitPolicy reject *:*
DisableDebuggerAttachment 0
"""


### Check TOR service


if(results.loadall):

        if("tor" in os.popen("ps -A | grep 'tor'").read()):
                print "TOR is working"
        else:
                print "Starting TOR service"
                os.popen("service tor stop")## check
                os.popen("service tor start")
                #check configuration



        if(torrc in  os.popen("cat /etc/tor/torrc").read()):
                print "TOR CONFIGURATION IS LOADED CORRECTLY"
        else:
                print "IP address mismatch...Are you trying to run tor on a different ip?"
                
                
                
                
                
##### TODO:
####  Add iptables rules to force all traffic except ssh and dns for management
###   Add torrc configuration file checker
##    Add install module to install tor via simple command and configure it with the script.. 
#     Add external support for Bridge/Exit Relay... and other rules 
#     Add Alternative VPN\proxy if tor fails
# example : ./boafiGate.py -install -ip 192.168.42.1 -loadall lan
  
