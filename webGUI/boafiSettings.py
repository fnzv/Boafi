#!/usr/bin/python

import os,time,argparse



parser = argparse.ArgumentParser()


parser.add_argument('-intf', action='store', dest='intf',default="none",
                    help='Select interface')

parser.add_argument('-ip', action='store', dest='ip',default="none",
                    help='Use given ip address')

parser.add_argument('-reboot', action='store', dest='reboot',default=False,
                    help='Reboot the machine')

parser.add_argument('-down', action='store', dest='down',default="none",
                    help='Shut given interface')

parser.add_argument('-up', action='store', dest='up',default="none",
                    help='Turn on given interface')

parser.add_argument('-restart', action='store', dest='restart',default="none",
                    help='Restart given service')

parser.add_argument('-ifstat', action='store', dest='ifstat',default="none",
                    help='Return bandwith values of given seconds')




results = parser.parse_args()
ip=results.ip
intf=results.intf
reboot=results.reboot
down=results.down
up=results.up
restart=results.restart
ifstat=results.ifstat


if not(intf=="none"):
        if(ip!="none"):
                os.popen("sudo ifconfig "+intf+" "+ip)
        else:
                print "no ip!"

if(reboot):
        os.popen("sudo reboot")

if not(up=="none"):
        os.popen("sudo ifconfig "+up+" up")
        print "Up interface"+up

if not(down=="none"):
        os.popen("sudo ifconfig "+down+" down")
        print "Up interface"+down


if not(restart=="none"):
        os.popen("sudo service "+restart+" restart")
        print "Restarted "+restart

if not(ifstat=="none"):
        secs=ifstat
        stats=os.popen("timeout "+secs+"s ifstat -t -q 0.5").read()
        print stats
