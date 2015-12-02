#####  BoafiHoney.py
###  - Creates a dns black hole and starts apache server (to run a Captive Portal or any web site)
##   - Dependencies : bind9,apache, (working hostspot.. dhcp & hostapd)
#    - Forces every client to connect to our websites (for every http requests redirect to --> localhost)
#    - HTTPs requests are blocked


###  Author: Yessou Sami 
###  Project Boafi
###  Tested on Raspberry pi 2(Raspian) with ALFA AWUS052NH
#!/usr/bin/python

import os,time,argparse

parser = argparse.ArgumentParser()


parser.add_argument('-SSID', action='store', default="Free WIFI",
                    dest='ssid',
                    help='Set this SSID name for the hostapd configuration ')


parser.add_argument('-blackhole', action='store_true', default=False,
                    dest='blackhole',
                    help='Run the honeypot with a dns blackhole that points to local captive portal ')

# Stealth honeypot  ---> Captive portal ----> Internet
#parser.add_argument('-stealth', action='store_true', default=False,
#                   dest='loadall',
#                  help='Start All the services and uses the ip address as Tor Gateway')





results = parser.parse_args()




ipaddr=str(os.popen("ifconfig wlan0 | grep 'inet addr' | awk -F: '{print $2}' | awk '{print $1}'").read())
#Get ip address of wlan0 interface with linux bash
## Another way to get all ip addresses of boafi --> hostname --all-ip-addresses
## OR hostname -I
ipaddr=ipaddr.strip()

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

print bind_cfg



APname=results.ssid

hostapd_cfg="""
interface=wlan0
driver=nl80211
ssid="""+APname+"""
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""


print hostapd_cfg
os.popen("sudo cp /etc/hostapd/hostapd.conf /etc/hostapd/cfg.backup") #Backup original config
cfg_check=os.path.exists("/etc/bind/db.catchall")

os.popen("service hostapd stop")
file= open("/etc/hostapd/hostapd.conf","w")
file.write(hostapd_cfg)
file.close()
os.popen("service hostapd start")


file=open("/etc/bind/named.conf.local","r")
named="""zone "." {
        type master;
        file "/etc/bind/db.catchall";
};"""


if(named in file.read()):
        print "IT's OK"
else:
        file2=open("/etc/bind/named.conf.local","a")
        file2.write(named)
        file2.close()
        print "Wrote named cfg"




if(results.blackhole):
        if not (cfg_check):
                file = open("/etc/bind/db.catchall", "wb")
                file.write(bind_cfg)
                file.close()
        os.popen("sudo service apache2 start")
        os.popen("sudo service bind9 start")
        #Started hostapd with the dnsblack hole configuration
        print "iptables -t nat -I PREROUTING -p tcp --dport 80 -j DNAT --to-destination "+ipaddr+":80"

        os.popen("iptables -t nat -I PREROUTING -p tcp --dport 80 -j DNAT --to-destination "+ipaddr+":80")
        os.popen("iptables -t nat -I PREROUTING -p tcp --dport 443 -j DNAT --to-destination "+ipaddr+":80")

        print "started hostapd"





##TODO
## Stealth captive portal
## Ip tables handling for other traffic (other ports 22,443,21,8080...) to block covert channels
## Log all IP,MAC,DNS Queries,Open Sockets of the clients connected
