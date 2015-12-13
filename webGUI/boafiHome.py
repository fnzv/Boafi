####
#### Script for Home\Index page 
#### 
#### -Get wifi AP list
#### -Turn off toggles for some boafi functions 
#### -..

##
#!/usr/bin/python

import os,time,argparse


parser = argparse.ArgumentParser()


parser.add_argument('-wifi', action='store_true', dest='wifi', default=False,
                    help='Get near-by wifi list')

parser.add_argument('-killCap', action='store_true', dest='killme', default=False,
                    help='Kill mac address gathering and shuts monitor interface')

parser.add_argument('-AutoCap', action='store_true', dest='autocap', default=False,
                    help='Adds to startup the AutoCapture function of BoafiCap')

parser.add_argument('-NoAutoCap', action='store_true', dest='noautocap', default=False,
                    help='Removes BoafiCap from start up')

parser.add_argument('-Honey', action='store_true', dest='honey', default=False,
                    help='Turn on honeypot')

parser.add_argument('-NoHoney', action='store_true', dest='nohoney', default=False,
                    help='Turn off honeypot')

parser.add_argument('-AutoHoney', action='store_true', dest='autohoney', default=False,
                    help='Adds to startup the honeypot')

parser.add_argument('-NoAutoHoney', action='store_true', dest='noautohoney', default=False,
                    help='Removes to startup the honeypot')

parser.add_argument('-NoPentest', action='store_true', dest='nopentest', default=False,
                    help='Turns Off any Pentesting attack currently running')

parser.add_argument('-FastMonitoring', action='store_true', dest='fmonitor', default=False,
                    help='Perform a quick scan on the network and shows online hosts,current connections,dns queri$

parser.add_argument('-SysInfo', action='store_true', dest='sysinfo', default=False,
                    help='Show Boafi Status (process,system data..)')




results = parser.parse_args()


wifi=results.wifi
killme=results.killme
autocap=results.autocap
noautocap=results.noautocap
honey=results.honey
nohoney=results.nohoney
autohoney=results.autohoney
noautohoney=results.noautohoney
nopentest=results.nopentest
fmonitor=results.fmonitor
sysinfo=results.sysinfo



if(wifi):
        file=open("wifiscan-"+str(time.time()),"w")
        ifconfig=os.popen("""ifconfig | grep "wlan" | awk '{ $2 = ""; $3 = ""; $4=""; $5=""; print }'ifconfig | grep "wlan" | awk '{ $2 = ""; $3 = ""; $4=""; $5=""; print }'""").read()
        interfaces=ifconfig.split()
        for wlan in interfaces:
                 print wlan
                 wifinets=os.popen("""iw dev """+wlan+""" scan ap-force | grep 'SSID' | awk '{ $1=""; print }'  """).read()

                 print wifinets
                 #other options : print on screen || write on file || write on db || or ?
                 file.write(wifinets)
        file.close()


if (killme):
        os.popen("killall airodump-ng")
        os.popen("ifconfig mon0 down")
        os.popen("ifconfig mon1 down")


if(autocap):
        boafiCap="@reboot sudo python "+(os.popen('pwd').read()).strip()+'/BoafiCap.py -csv -pcap -o AutoCapture'
        #Must be on the same directory of BoafiCap
        print boafiCap
        ## MUST be root to edit crontab  ##
        os.popen("sudo echo '"+boafiCap+"' >> /var/spool/cron/crontabs/root")

if(noautocap):
        boafiCap="@reboot sudo python "+(os.popen('pwd').read()).strip()+'/BoafiCap.py -csv -pcap -o AutoCapture'
        crontab="/var/spool/cron/crontabs/root"
        filecron=open(crontab).read()
        open(crontab,"w").write(filecron.replace(boafiCap,""))

if(honey):
        #turn on honeypot
        os.popen("sudo python BoafiHoney.py -blackhole")

if(nohoney):
        #turn off honeypot
        os.popen("sudo python BoafiHoney.py -off")


if(autohoney):
        #adds to crontab the script
        boafiHoney="@reboot sudo python "+(os.popen('pwd').read()).strip()+'/BoafiHoney.py -blackhole'
        os.popen("sudo echo '"+boafiHoney+"' >> /var/spool/cron/crontabs/root")

if(noautohoney):
        #removes from startup
        boafiHoney="@reboot sudo python "+(os.popen('pwd').read()).strip()+'/BoafiHoney.py -blackhole'
        crontab="/var/spool/cron/crontabs/root"
        filecron=open(crontab).read()
        open(crontab,"w").write(filecron.replace(boafiHoney,""))

if(nopentest):
        os.popen("boafiPentest.py -shut")





