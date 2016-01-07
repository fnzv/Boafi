#!/usr/bin/python

import os,time,argparse



parser = argparse.ArgumentParser()

parser.add_argument('-connectwpa', action='store', dest='connectwpa', default="none",
                    help='Connect to given WPA wifi network with wlan interface... Network:password-wlan0.. if not specified interface will take wlan0')

parser.add_argument('-connect', action='store', dest='connect', default="none",
                    help='Connect to given open wifi network with given wlan interface... FreeWifi-wlan0')

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

parser.add_argument('-updatecap', action='store_true', dest='updatecap',default=False,
                    help='Add crontab to Update every 5 minutes capture file for webGUI')





results = parser.parse_args()
ip=results.ip
intf=results.intf
reboot=results.reboot
down=results.down
up=results.up
restart=results.restart
ifstat=results.ifstat
connect=results.connect
connectwpa=results.connectwpa
updatecap=results.updatecap

if not(connectwpa=="none"):# -connectwpa WifiNet:password

        net=connectwpa.split(":")[0]
        password=connectwpa.split(":")[1]
        interface=connectwpa.split("-")[1]
        os.popen("sudo wpa_passphrase "+net+" "+password+" > "+net)
        os.popen("sudo nohup wpa_supplicant -i wlan0 -c "+net+" >/dev/null 2>&1 &") ## DHCP should be automatically assigned via wpa_supplicant
          # -D n180211 ALFA driver.. but works even without using specific drivers

if not(connect=="none"):
        try:
           interface=connect.split("-")[1]
           network=connect.split("-")[0]
        except:
            network=connect
            interface="wlan0"
        if("-" not in connect):
          print os.popen("sudo iw dev wlan0 connect "+network).read()
          os.popen("dhcpcd wlan0")
        else:  
          print os.popen("sudo iw dev "+inteface+" connect "+network).read()
          os.popen("dhcpcd "+interface)

if(updatecap):
      os.popen("sudo cd /root")
      recent=os.popen("ls -t | head -n 1").read().strip()
      print recent
      os.popen("cp "+recent+" /var/www/BDashboard/PhpScripts/CsvFile.csv")
      print "Updated .csv file to last captured!"
      

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
