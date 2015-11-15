#!/usr/bin/python
import os,time,argparse

#####  BoafiHoney.py
###  - Creates a dns black hole and starts apache server (to run a Captive Portal or any web site)
##   - Dependencies : bind9,apache
#    - Forces every client to connect to our websites (for every http requests redirect to --> localhost)
#    - HTTPs requests are blocked


###  Author: Yessou Sami 
###  Project Boafi
###  Tested on Raspberry pi 2(Raspian) with ALFA AWUS052NH




parser = argparse.ArgumentParser()




parser.add_argument('-blackhole', action='store_true', default=False,
                    dest='blackhole',
                    help='Run the honeypot with a dns blackhole that points to local captive portal ')

# Stealth honeypot  ---> Captive portal ----> Internet
#parser.add_argument('-stealth', action='store_true', default=False,
#                   dest='loadall',
#                  help='Start Captive Portal only one time')





results = parser.parse_args()





ipaddr=str(os.popen("ifconfig wlan0 | grep 'inet addr' | awk -F: '{print $2}' | awk '{print $1}'").read())
#Get ip address of wlan0 interface with linux bash
## Another way to get all ip addresses of boafi --> hostname --all-ip-addresses
## OR hostname -I


###
###
##
# Start apache2 server
# Start dns server black hole
# Log all connections to a file in append( DHCP Logs,MACs...)




#Check configurations

#bind configuration for DNS BLACK HOLE
bind_cfg="""$TTL    604800
@       IN      SOA     . root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

        IN      NS      .
.       IN      A       """+ipaddr+"""
*.      IN      A       """+ipaddr



cfg_check=os.path.exists("/etc/bind/db.catchall") #Check if the dns configuration exists 



if(results.blackhole and not cfg_check):
        # Write the dns black hole configuration
        file = open("/etc/bind/db.catchall", "wb")
        file.write(bind_cfg)
        file.close()
        #Start services
        os.popen("service apache2 start") # You need to have your files of the captive portal on your /var/www
        os.popen("service bind9 start") # Starting bind dns for black hole
        print "Started Captive Portal"

##TODO
## Stealth captive portal
## Ip tables handling for other traffic (other ports 22,443,21,8080...) to block covert channels
## Log all IP,MAC,DNS Queries,Open Sockets of the clients connected
