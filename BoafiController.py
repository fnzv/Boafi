#!/usr/bin/python

import os,time


#####  BoafiController.py
###  - Check running services and fix errors
##   - Dependencies : hostapd,isc-dhcp-server (ip addr 192.168.42.1)
#    - Fix wlan0 address if the network interfaces get APIPA address and fail to start dhcp,hostapd services
#    - Save logs in Controller.logs with various information about the system



###  Author: Yessou Sami 
###  Project Boafi
###  Tested on Raspberry pi 2(Raspian) with ALFA AWUS052NH



if("airodump" in os.popen("ps -A | grep 'airodump' ").read()):
        #Boafi is still capturing pcap\csv
        capture="ON"
        #print "YEP i'm capturing data"
else:
        capture="OFF"


if("hostapd" in os.popen("ps -A | grep 'hostapd' ").read()):
        hostapd="ON"
else:
        hostapd="OFF"

if("dhcp" in os.popen("ps -A | grep 'dhcp' ").read()):
        dhcp="ON"
else:
        dhcp="OFF"
if("apache" in os.popen("ps -A | grep 'apache' ").read()):
        www="ON"
else:
        www="OFF"


print "\t\tBoafi STATUS:"
print "Capture: \t\t\t",capture
print "Access Point: \t\t\t",hostapd
print "DHCP Server: \t\t\t",dhcp
print "APACHE Server: \t\t\t",www

fixed="NOPE"

############################
## FIX no address ERROR on DHCPD and HOSTAPD
if( "192.168.42.1" not in os.popen("ifconfig wlan0").read() ):
        os.popen("ifconfig wlan0 192.168.42.1")
        print os.popen("ifconfig wlan0").read()
        print "FIXED IP\n"
        os.popen("service isc-dhcp-server restart")
        print "RESTARTING DHCP server"
        os.popen("service hostapd restart")
        print "RESTARTING HOSTAPD"
        fixed="YES"
#### check wireless AP 
wifinets=os.popen("iw dev wlan0 scan ap-force | grep 'SSID' ").read()

print wifinets



logs = open("Controller.logs","a")
logs.write("GENERAL DATA: CAPTURE-"+capture+"|HOSTAPD-"+hostapd+"|DHCP "+dhcp+"|APACHE: "+www )
logs.write("CURRENT WIFI NETS DURING SCRIPT START:"+wifinets)
logs.write("FIXED:"+fixed)
logs.write("TIME:"+time.strftime("%c")+"\n\n")
logs.close()


## TODO
## Allow BoafiController to kill BoafiCap when requested from WebApp GUI
## Auto-Run this script after a delay to check for common errors?
## Auto-Fix other errors if any
## Check temperature of device and halt if too hot



