#!/usr/bin/python
####
#### Script for Home\Index page 
#### 
#### -Get wifi AP list
#### -Turn off toggles for some boafi functions 
#### -..

##
import os,time,argparse


parser = argparse.ArgumentParser()


parser.add_argument('-wifi', action='store_true', dest='wifi', default=False,
                    help='Get near-by wifi list')


parser.add_argument('-killCap', action='store_true', dest='killme', default=False,
                    help='Kill mac address gathering and shuts monitor interface')



results = parser.parse_args()



wifi=results.wifi
killme=results.killme





if(wifi):
        file=open("wifiscan-"+str(time.time()),"w")
        ifconfig=os.popen("""ifconfig | grep "wlan" | awk '{ $2 = ""; $3 = ""; $4=""; $5=""; print }'ifconfig | grep "wlan" | awk '{ $2 = ""; $3 = ""; $4=""; $5=""; print }'""").read()
        interfaces=ifconfig.split()
        for wlan in interfaces:
                 print wlan
                 wifinets=os.popen("""iw dev """+wlan+""" scan ap-force | grep 'SSID' | awk '{ $1=""; print }'  """).read()

                 print wifinets
                 #print on screen || write on file || write on db || or ?
                 file.write(wifinets)
        file.close()


if (killme):
        os.popen("killall airodump-ng")
        os.popen("ifconfig mon0 down")
        

