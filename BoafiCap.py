#!/usr/bin/python

import os,time,sys,subprocess
import argparse


def EnaMon():
        #Refreshing interfaces
        os.system("airmon-ng stop mon0")
        #Starting Monitor mode mon0
        os.system("airmon-ng start wlan0")


#####  BoafiCap.py
###  - Capture all wireless networks and output them into csv\pcap files
##   - Dependencies : aircrack-ng
#    - Running in background once started and must be killed with an external script or via bash kill
#    - Maintains aircrack-ng output format for more compatibility


###  Author: Yessou Sami 
###  Project Boafi
###  Tested on Raspberry pi 2(Raspian) with ALFA AWUS052NH

parser = argparse.ArgumentParser()


parser.add_argument('-timeout', action='store', dest='timeout', default="none",
                    help='Define given seconds before the capture timeouts if not specified will run until its killed')


parser.add_argument('-o', action='store', dest='output',
                    help='Output file name without extension..if empty i will use ( dump.extension ) ')


parser.add_argument('-t', action='store', dest='time',
                    help='Write time interval')


parser.add_argument('-csv', action='store_true', default=False,
                    dest='csvmode',
                    help='Set csv mode ')


parser.add_argument('-pcap', action='store_true', default=False,
                    dest='pcapmode',
                    help='Set pcap mode')


time=""
time+=results.time
results = parser.parse_args()

csvmode=results.csvmode
if not(results.timeout=="none"):
        timeout="timeout "+results.timeout+"s "
        print "\n\nTimeout set for seconds:"+results.timeout
else:
        timeout=""


if results.output !=" " :
        output_file=results.output
else :
        output_file="dump"

pcapmode=results.pcapmode

if results.time !="" :
    time=int(results.time)
    

EnaMon()
print "mon0 Enabled \n\n"
time.sleep(2)
print "Starting capturing wifi networks  nearby\n\n"

if pcapmode and csvmode :
        cmd="nohup "+timeout+"airodump-ng mon0 -w "+output_file+" --output-format csv,cap -t "+time+" >/dev/null 2>&1 &"
elif pcapmode :
        cmd="nohup "+timeout+"airodump-ng mon0 -w "+output_file+" --output-format cap -t "+time+" >/dev/null 2>&1 &"
elif csvmode :
        cmd="nohup "+timeout+"airodump-ng mon0 -w "+output_file+" --output-format csv  -t "+time+"  >/dev/null 2>&1 &"


os.system(cmd)

print "Starting capturing packets"



# ill add other options like
# --ivs save only IV
# -f time between hopping from one channel to another
# -C <frequencies>



