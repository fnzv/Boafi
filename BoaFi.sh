echo "BoaFi configuration script v0.1"
sudo su
echo "Checking..."
apt-get update
echo "Installing packages..."
apt-get install -y aircrack-ng apache2 php5 bind9 isc-dhcp-server hostapd
echo "Done.
Configuring hostapd... Please insert the WiFi Network name: "
read network
echo "interface=wlan0
driver=nl80211
ssid=$network
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
#wpa=2 //commented: open network
#wpa_passphrase=1337
#wpa_key_mgmt=WPA-PSK
#wpa_pairwise=TKIP
#rsn_pairwise=CCMP" > /etc/hostapd/hostapd.conf
echo "Done.
Configuring bind9..."
echo 'zone "." {
type master;
file "/etc/bind/db.catchall";
};' >> /etc/bind/named.conf.local
echo "$TTL    604800
@       IN      SOA     . root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
        IN      NS      .
.       IN      A       192.168.42.1
*.      IN      A       192.168.42.1" > /etc/bind/db.catchall
echo "Done.
Configuring isc-dhcp-server..."
echo '######
###### Working configuration for isc-dhcp-server tested on Raspberry pi 2 B
######
######

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ("none", since DHCP v2 didnt
# have support for DDNS.)
ddns-update-style none;

# option definitions common to all supported networks...
#option domain-name "example.org";
#option domain-name-servers ns1.example.org, ns2.example.org;

default-lease-time 600;
max-lease-time 7200;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
log-facility local7;

# No service will be given on this subnet, but declaring it helps the
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we dont really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
#  default-lease-time 600;
#  max-lease-time 7200;
#}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.fugue.com";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.fugue.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of "foo";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of "foo";
#    range 10.0.29.10 10.0.29.230;
#  }
#}

subnet 192.168.42.0 netmask 255.255.255.0{
 range 192.168.42.10 192.168.42.255;
 option broadcast-address 192.168.42.255;
 option routers 192.168.42.1;
 default-lease-time 7000;
 max-lease-time 9000;
 option domain-name "local"; #optional
 option domain-name-servers 192.168.42.1,192.168.42.1;  #optional
}' > /etc/dhcpd/dhcp.conf
echo "Done.
Configuring other stuff..."
echo '# Generated by iptables-save v1.4.21 on Fri Oct 30 09:52:00 2015
*filter
:INPUT ACCEPT [1298:81983]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [811:164861]
-A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i wlan0 -o eth0 -j ACCEPT
COMMIT
# Completed on Fri Oct 30 09:52:00 2015
# Generated by iptables-save v1.4.21 on Fri Oct 30 09:52:00 2015
*nat
:PREROUTING ACCEPT [72:6316]
:INPUT ACCEPT [21:1273]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -m tcp --dport 443 -j DNAT --to-destination 192.168.42.1
-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.42.1
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
# Completed on Fri Oct 30 09:52:00 2015' > /etc/iptables/rules.v4
echo "Done!"
