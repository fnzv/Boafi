#!/usr/bin/python
### Boafi uses Smart Detecton System as local firewall\monitoring system 
###
### Dependencies: arpspoof,nmap (for mitm)
###               iptables
###               bootstrap (future GUI)
###  Author: Yessou Sami 
###  Project Boafi

import os,time,argparse,socket,pprint



parser = argparse.ArgumentParser()


parser.add_argument('-banCountry', action='store', default="none",
                    dest='bancountry',
                    help='Ban all IP addresses coming from given country italy--> it ..pakistan --> pk')

parser.add_argument('-proxy', action='store', default="none",
                    dest='loadproxy',
                    help='Route HTTP and HTTPS traffic to an Internal or External Transparent Proxy .. \n Example: -proxy 192.168.1.5:3128')

parser.add_argument('-trafficlimit', action='store', default="none",
                    dest='trafflimit',
                    help='Limit traffic rate... 10/s = 10 packet per second .. 10/m = 10 per minute ..10/h per hour')

parser.add_argument('-timerange', action='store', default="none",
                    dest='timerange',
                    help='Time range intervall that will be applied on rule or SDS argument \nExample: -timerange 09:00,18:00 ')

parser.add_argument('-log', action='store_true', default=False,
                    dest='log',
                    help='Enable packets logging on /var/log')
                    
parser.add_argument('--blacklist', action='store', default="none",
                    dest='blacklist',
                    help='Load a list with banned keywords\IP\Domains that will be applied on the firewall')
            
parser.add_argument('--whitelist', action='store', default="none",
                    dest='whitelist',
                    help='Load a list with the only permitted keywords\IP\Domains on the firewall')

parser.add_argument('--loadpcap', action='store', default="none",
                    dest='loadpcap',
                    help='Load a list with banned keywords\IP\Domains that will be applied on the firewall')
                    
parser.add_argument('--loadweb', action='store', default="none",
                    dest='loadweb',
                    help='Load a list with banned keywords\IP\Domains from the web')
                    
parser.add_argument('--GUI', action='store_true', default=False,
                    dest='gui',
                    help='Load the webGUI and start browser to check stats\traffic analysis')  
                    
parser.add_argument('--nopolicy', action='store', default="none",
                    dest='nopolicy',
                    help='Set "DENY" default policy on given CHAIN.. example: FORWARD,INPUT,OUTPUT')    
                    
parser.add_argument('--yespolicy', action='store', default="none",
                    dest='yespolicy',
                    help='Set "ACCEPT" default policy on given CHAIN.. example: FORWARD,INPUT,OUTPUT')    
                    
parser.add_argument('--captiveportal', action='store', default="none",
                    dest='captive',
                    help='Enable the captive portal and any address is being redirected to the given address')    

parser.add_argument('--dns-redirect', action='store', default="none",
                    dest='dnsre',
                    help='Redirect all DNS queries to given dns sever address')   

parser.add_argument('--no-dns', action='store_true', default=False,
                    dest='nodns',
                    help='Removes DNS redirect')
                  
parser.add_argument('--icmp-redirect', action='store', default="none",
                    dest='icmpre',
                    help='Redirect all ICMP Requests to given address')   

parser.add_argument('--no-icmp', action='store_true', default=False,
                    dest='noicmp',
                    help='Removes ICMP redirect')
                    

parser.add_argument('-R', action='store_true', default=False,
                    dest='flush',
                    help='Restore default iptables rules')

parser.add_argument('-S', action='store_true', default=False,
                    dest='save',
                    help='Save iptables rules on startup **warning** deletes old ones')
                    
parser.add_argument('-killmitm', action='store_true', default=False,
                    dest='killmitm',
                    help='Kill any Offensive SDS Firewall doing mitm')


parser.add_argument('-rule', action='store', dest='rule', default=False, help='Manually create firewall rules via an easy syntax language')


parser.add_argument('--deny', action='store', dest='denyrules', default="none", help='Write deny rules')



parser.add_argument('--permit', action='store', dest='permitrules', default="none", help='Write permit rules')


##Still alpha.. not implemented mitm firewall yet
parser.add_argument('--spoof', action='store', default="none", dest='spoof', help='Force Firewall to all hosts even if not connected to our machine directly..\n Specify Default gateway')


results = parser.parse_args()

if not(results.timerange=="none"): #09:00,18:00
        interval=results.timerange
        interval=interval.split(",")
        print "interval: "+interval
        time1=interval[0]
        time2=interval[1]
        timeout="-m time --timestart "+time1+" --timestop "+time2
else:
        timeout=""



if not(results.bancountry=="none"): ## Could take some time.. ip lists are big..contain all ip ranges of countries
      ## example : italy - it ,pakistan - pk, russia - ru, united states - us ,
      ## If you run iptables -L could take some minutes!!! 
      code=results.bancountry
      iplist=os.popen("curl  http://www.ipdeny.com/ipblocks/data/countries/"+code+".zone").read()
      iplist=iplist.split()
      for ip in iplist:
        os.popen("iptables -I FORWARD -d "+ip+" -j DROP")
        os.popen("iptables -I INPUT -d "+ip+" -j DROP")
        os.popen("iptables -I OUTPUT -d "+ip+" -j DROP")
        print ip+" DENIED"
      
      


if not (results.trafflimit=="none"):
      tl=results.trafflimit
      ## TODO :Control string error 
      os.popen("iptables -I INPUT -p tcp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")
      os.popen("iptables -I OUTPUT -p tcp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")
      os.popen("iptables -I FORWARD -p tcp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")
      os.popen("iptables -I INPUT -p udp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")
      os.popen("iptables -I OUTPUT -p udp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")
      os.popen("iptables -I FORWARD -p udp -m limit --limit "+tl+" "+timeout+" -j ACCEPT")


if not(results.loadpcap == "none"):
                        print "Reading capture file and parsing ip addresses"
                        print "Only ip addresses found on .pcap will be allowed to pass on this firewall"
                        try:
                                allowedIP=os.popen("""tshark  -o column.format:'"Source", "%s"' -r """+results.loadpcap+" |sort|uniq").read()
                                print allowedIP
                                for line in allowedIP.split():
                                        try:
                                                 socket.inet_aton(line)
                                                 print "Loaded from pcap  ",line
                                                 os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp "+timeout+" -j ACCEPT")
                                        except:
                                                print "This isn't an IP"
                                os.popen("iptables -P FORWARD DROP")
                        except:
                                print "Error Parsing capture"
if not(results.blacklist =="none"):  
                            blacklist=results.blacklist
                            try:
                                f=open(blacklist,"r") #Open external file to see what sites can't pass our gateway
                                filterlist=f.read()  # list based on keywords
                                for line in filterlist.split(): #Apply URL Filterbased firewall
                                        if(";" in line): # ignore line cuz its a comment
                                                print "Ignore comment"
                                        else:   # Execute filtering
                                                try:
                                                        socket.inet_aton(line)
                                                        print "I'm an ipv4! ",line
                                                        #if i'm here cuz line is an ipv4 address
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp  -j DROP")
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp  -j LOG --log-prefix 'BLACKLIST-SDS'")
                                                except: # if i'm there cuz its not an ipv4 so a normal string
                                                        os.popen("iptables -I FORWARD -p tcp --match multiport --dports 80,443 -m string --string "+line+" --algo kmp -j DROP")
                                                        os.popen("iptables -I FORWARD -p udp --dport 53 -m string --string "+line+" --algo kmp -j DROP")
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp -j LOG --log-prefix 'BLACKLIST-SDS'")
                                                        print "added blacklist rule: ",line
                            except:
                                print "Can't load filter list"
if not(results.whitelist =="none"):  
                            whitelist=results.whitelist
                            try:
                                f=open(whitelist,"r") #Open external file to see what sites can pass our gateway
                                filterlist=f.read() 
                                for line in filterlist.split(): 
                                        if(";" in line): 
                                                print "Ignore comment"
                                        else:   
                                                try:
                                                        socket.inet_aton(line)
                                                        print "I'm an ipv4! ",line
                                                        #if i'm here cuz line is an ipv4 address
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp "+timeout+" -j ACCEPT")
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp -j LOG --log-prefix 'WHITELIST-SDS'")
                                                except: # if i'm there cuz its not an ipv4 so a normal string
                                                        os.popen("iptables -I FORWARD -p tcp --match multiport --dports 80,443 -m string --string "+line+" --algo kmp "+timeout+" -j ACCEPT")
                                                        os.popen("iptables -I FORWARD -p udp --dport 53 -m string --string "+line+" --algo kmp "+timeout+" -j ACCEPT")
                                                        os.popen("iptables -I FORWARD -p ALL -m string --string  "+line+" --algo kmp -j LOG --log-prefix 'WHITELIST-SDS'")
                                                        print "added whitelist rule: ",line
                            except:
                                print "Can't load filter list"


if not(results.nopolicy == "none"):
    chain=results.nopolicy
    os.popen("iptables -P "+chain+" DENY")
    os.popen("iptables -I "+chain+" -p ALL -j LOG --log-prefix 'POLICY-SDS'")

if not(results.yespolicy == "none"):
    chain=results.yespolicy
    os.popen("iptables -P "+chain+" ACCEPT")
    os.popen("iptables -I "+chain+" -p ALL -j LOG --log-prefix 'POLICY-SDS'")
    

if(results.log): #Full Logger.. then Grab data from syslog and save it into database( mysql)
    os.popen("iptables -I FORWARD -p all -j LOG --log-prefix 'GENERAL-LOG'")
        #Start Logging every connection to /var/log/messages

    #Log also images on /tmp?
    os.popen("iptables -I FORWARD -p all -m string --string 'jpg' --algo kmp  -j LOG --log-prefix 'JPG-SDS'")
    os.popen("iptables -I FORWARD -p all -m string --string 'gif' --algo kmp  -j LOG --log-prefix 'GIF-SDS'")
    os.popen("iptables -I FORWARD -p all -m string --string 'png' --algo kmp  -j LOG --log-prefix 'PNG-SDS'")
    os.popen("iptables -I FORWARD -p all -m string --string 'mp4' --algo kmp  -j LOG --log-prefix 'MP4-SDS'")
    #Log urls/web request
    os.popen("iptables -I FORWARD -p tcp -m multiport --dports 80,443 -j LOG --log-prefix 'WWW-SDS' ")
    #Log DNS
    os.popen("iptables -I FORWARD -p udp --dport 53 -j LOG --log-prefix 'DNS-SDS'")
    #Log credentials HTTP
    os.popen("iptables -I FORWARD -p all -m string --string 'pass' --algo kmp -j LOG --log-prefix 'PASSWORD-SDS'")
    os.popen("iptables -I FORWARD -p all -m string --string 'user' --algo kmp  -j LOG --log-prefix 'USERNAME-SDS'")
    

if(results.flush): #Restore iptables
        os.popen("iptables-restore < /etc/iptables/rules.v4")
   

if not(results.captive== "none"):
        cpIP=results.captive
        os.popen("iptables -P FORWARD DENY")
        os.popen("iptables -P PREROUTING DENY")
        os.popen("iptables -P POSTROUTING DENY")
        os.popen("iptables -t nat -I PREROUTING -p tcp --dport 443 "+timeout+" -j DNAT --to-destination "+cpIP+":80")
        os.popen("iptables -t nat -I PREROUTING -p tcp --dport 80 "+timeout+" -j DNAT --to-destination "+cpIP+":80")
        ###
        #### Do Captive portal.. when registered allow user to browse internet or make policies to allow certain sites etc..
        
if not(results.dnsre =="none"):
       dnsServer=results.dnsre
       os.popen("iptables -t nat -I PREROUTING -p udp --dport 53 "+timeout+" -j DNAT --to-destination "+dnsServer+":53")
       

if(results.nodns):
        ip=os.popen("""iptables -t nat -L PREROUTING  | grep "domain to:" | awk '{ print $8; exit }'""").read().replace("to:","")
        cleanip=ip.strip()
        os.popen("iptables -t nat -D PREROUTING -p udp --dport 53 "+timeout+" -j DNAT --to-destination "+cleanip)


if(results.icmpre == "none"):
      fakedest=results.icmpre
      os.popen("iptables -t nat -I PREROUTING -p icmp --icmp-type echo-request "+timeout+" -j DNAT --to-destination "+fakedest)

if(results.noicmp):
        ip=os.popen("""iptables -t nat -L PREROUTING  | grep "icmp echo-request to:" | awk '{ print $8; exit }'""").read().replace("to:","")
        cleanip=ip.strip()
        os.popen("iptables -t nat -D PREROUTING -p icmp --icmp-type echo-request "+timeout+" -j DNAT --to-destination "+cleanip)

if(results.save):
        os.popen("iptables-save >> /etc/iptables/rules.v4")
        print "Saved rules!"

if(results.rule):

 #Read values from ARGS and send them directly to iptables
#Static IP tables rules...
  deny=str(results.denyrules)
  print "using rules ",deny
  if("tcp" in deny):
   
      if("http" in deny):
         os.popen("iptables -I FORWARD -p tcp --dport 80 "+timeout+" -j DROP")
      if("https" in deny):
        os.popen("iptables -I FORWARD -p tcp --dport 443 "+timeout+" -j DROP")
      if("ftp" in deny):
        os.popen("iptables -I FORWARD -p tcp --dport 21 "+timeout+" -j DROP")
      if("icmp" in deny):
         os.popen("iptables -I FORWARD -p icmp --icmp-type 8 "+timeout+" -j DROP")
      if("dns" in deny):
         os.popen("iptables -I FORWARD -p udp --dport 53 "+timeout+" -j DROP")
  ### PERMIT RULES
  permit=str(results.permitrules)
  print "using rules ",permit
  if("tcp" in permit):
  
     if("http" in permit):
          os.popen("iptables -I FORWARD -p tcp --dport 80 "+timeout+" -j ACCEPT")
     if("https" in permit):
         os.popen("iptables -I FORWARD -p tcp --dport 443 "+timeout+" -j ACCEPT")
     if("ftp" in permit):
         os.popen("iptables -I FORWARD -p tcp --dport 21 "+timeout+" -j ACCEPT")
     if("icmp" in permit):
        os.popen("iptables -I FORWARD -p icmp --icmp-type 8 "+timeout+" -j ACCEPT")
     if("dns" in permit):
         os.popen("iptables -I FORWARD -p udp --dport 53 "+timeout+" -j ACCEPT")
         
if not(results.spoof=="none"): #Works slowly(256 pings) but once has started all arpspoof jobs it's done
        ipnet=results.spoof  # Example : 192.168.1.0/24 .
        iplist=os.popen("nmap -sP "+ipnet+" | grep 'Nmap scan' | awk '{ print $5; }'").read()
        iplist=iplist.split()
        dgip=os.popen("ip route show | grep 'default' | awk '{print $3}' ").read()
        dgip=dgip.split()[0]
        print "Spoofing "+dgip+"\n\n"
        for ip in iplist:
                print ip
                os.popen("nohup arpspoof -t "+ip+" "+dgip+" >/dev/null 2>&1 &")

if not(results.loadproxy=="none"): ## ONLY HTTP & HTTPS
                # Proxy should be (socket format or just ip)  example 192.168.1.1:3128 or 1.1.1.1 
                #can be an external proxy or local
                proxy=results.loadproxy
                os.popen("iptables -t nat -A PREROUTING -m multiport -p tcp --dports 80,443 -j DNAT --to "+proxy)
                os.popen("iptables -t nat -I FORWARD -d "+proxy+" -j ACCEPT")
    


if(results.killmitm):
    os.popen("killall arpspoof")
    os.popen("killall tcpkill")
    


