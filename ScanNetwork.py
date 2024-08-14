import time
import subprocess
import socket
import select
import sys
import os
import struct
import dns.resolver
import netifaces
import subprocess
import re
import csv

#pip install zeroconf
from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceStateChange,
    Zeroconf
)

VERSION = "1.0.1"

strScriptName   = os.path.basename(sys.argv[0])
strScriptBase   = strScriptName.replace(".py","")
strScriptPath   = os.path.dirname(os.path.realpath(sys.argv[0]))
logFileName     = strScriptPath + "\\" + strScriptName.replace(".py", ".log")
csvFileName     = strScriptPath + "\\" + strScriptName.replace(".py", ".csv")

prop            = False
dictPorts       = {}
ipalive         = []  


DOPORTSCAN      = True
DOMDNS          = True
DOPING          = True

#----------------------------------------------------------------------------------
ICMP_ECHO_REQUEST = 8 # Platform specific
DEFAULT_COUNT     = 3
DEFAULT_SIZE      = 64
DEFAULT_TIMEOUT   = 300   #in milliseconds

class Pinger(object):
    """ Pings to a host -- the Pythonic way"""

    def __init__(self, target_host, count=DEFAULT_COUNT, size=DEFAULT_SIZE, timeout=DEFAULT_TIMEOUT, debug=False):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout / 1000  # convert to seconds - select uses seconds
        self.size = size
        self.debug = debug

    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while count < max_count:
            val = source_string[count + 1]*256 + source_string[count]
            sum = sum + val
            sum = sum & 0xffffffff
            count = count + 2

        if max_count<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff

        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def receive_pong(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if readable[0] == []: # Timeout
                return

            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return


    def send_ping(self, sock,  ID):
        """
        Send ping to the target host
        """
        target_addr  =  socket.gethostbyname(self.target_host)

        my_checksum = 0

        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + bytes(data.encode('utf-8'))

        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
        packet = header + data
        sock.sendto(packet, (target_addr, 1))


    def ping_once(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e:
            if e.errno == 1:
                # Not superuser, so operation not permitted
                e.msg +=  "ICMP messages can only be sent from root user processes"
                raise socket.error(e.msg)
        except Exception as e:
            if self.debug:
                print("Exception: %s" %(e))

        my_ID = os.getpid() & 0xFFFF

        self.send_ping(sock, my_ID)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay


    def ping(self):
        """
        Run the ping process
        """
        
        max=0
        min=0
        los=0
        tot=0
        
        for i in range(self.count):
            try:
                delay  =  self.ping_once()
            except socket.gaierror as e:
                if self.debug:
                    print("Ping failed. (socket error: '%s')" % e[1])
                    break

            if delay  ==  None:
                # print("Ping failed. (timeout within %ssec.)" % self.timeout)
                if self.debug:
                    print("Request timed out.")
                delay = int(self.timeout * 1000)
                los = los+1
                
            else:
                delay  =  int(delay * 1000)
                if self.debug:
                    print("Reply from %s" % self.target_host,end = '')
                    print(" time=%0.0fms" % delay)
            
            if delay > max:
                max=delay
            if delay < min:
                min=delay
            tot = tot + delay
            
        los = int((los/self.count)*100)
        return max, min, int(tot/self.count), los
#----------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def getargs(argv):

    global DOPORTSCAN, DOMDNS, DOPING
    global filename
    
    try:
        opts, args = getopt.getopt(argv,"?HPMF")
        
    except getopt.GetoptError:
        print(strScriptName + " (Version: " + VERSION + ") [-P or -M or -F]")
        print(" -P : skip Ping scan")
        print(" -M : skip MDNS scan")
        print(" -F : skip Port scan\n")
        print("  Default, a ping scan, a mDNS scan and port scan is done\n")
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-P':
            DOPING = False
            break
            
        elif opt == '-M':
            DOMDNS = False
            break
            
        elif opt == '-F':
            DOPORTSCAN = False
            break
        
        elif opt == "-H" or opt == "-?":
            print(strScriptName + " (Version: " + VERSION + ") [-P or -M or -F]")
            print(" -P : skip Ping scan")
            print(" -M : skip MDNS scan")
            print(" -F : skip Port scan\n")
            print("  Default, a ping scan, a mDNS scan and port scan is done\n")
#------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def doping(ip, Count, Size, Timeout, Debug):

    min=Timeout
    max=Timeout
    avg=Timeout
    los=100

    pinger = Pinger(target_host=ip, count=Count, size=Size, timeout=Timeout, debug=Debug)
    max, min, avg, los = pinger.ping()
              
    if Debug:
        print(min, max, avg, los)
    
    return min, max, avg, los, ip
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def checkip(ip):

    pinger = Pinger(target_host=ip, count=3, size=128, timeout=150, debug=False)
    max, min, avg, los = pinger.ping()

    if los == 0:
        return True
    else:
        return False
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def scan_ip_range(startIP, endIP):
    
    global ipalive
    
    # Convert IP addresses to integers
    start = list(map(int, startIP.split('.')))
    end = list(map(int, endIP.split('.')))

    # Generate IP range
    for i in range(start[0], end[0] + 1):
        for j in range(start[1], end[1] + 1):
            for k in range(start[2], end[2] + 1):
                for l in range(start[3], end[3] + 1):
                    ip = f"{i}.{j}.{k}.{l}"
                    min, max, avg, loss, ip = doping(ip, 3, 128, 150, False)
                    if loss == 0:
                        try:
                            host, _, _ = socket.gethostbyaddr(ip)
                        except:
                            host = "<not in DNS>"
                        # Run the arp command to get the MAC address
                        arp_command = ['arp', '-a', ip]
                        output = subprocess.check_output(arp_command).decode()
                        # Use regex to find the MAC address in the output
                        mac_address = re.search(r'(([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2})', output)
                        if mac_address:
                            mac = mac_address.group(0).replace('-', ':')
                        else:
                            mac = ""
                        print("{0:15s} [{2:17s}] - {1:32s} is alive".format(ip, host, mac))
                        log.write("{0:15s} [{2:17s}] - {1:32s} is alive\n".format(ip, host, mac))
                        
                        ipalive.append(ip)
                        
                    elif loss == 100:
                        print("{0:50s}                     is NOT reachable".format(ip))
                        log.write("{0:50s}                     is NOT reachable\n".format(ip))
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def on_service_state_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:

    global t_end, prop

    addr = ""
    mac  = ""
    host = ""
    
    if state_change is ServiceStateChange.Added:
        
        device = name.replace(service_type, "")[:-1]
        info = zeroconf.get_service_info(service_type, name)

        if info:
            # only get first IP address
            for addr in info.parsed_scoped_addresses():
                break
            
            # check ipf IP address is IPV4
            if len(addr) <= 15:
                try:
                    socket.inet_aton(addr)
                    #get MAC address
                    mac = get_mac_address(addr)
                    try:
                        host, _, _ = socket.gethostbyaddr(ip)
                    except:
                        host = "<not in DNS>"
                except socket.error:
                    addr = "               "
                    mac  = "                 "
            else:
                addr = "<" + addr[0:13] + ">"
                mac  = "                 "

            if mac and len(mac) == 17:
                print("  -> {0:50s} on {1:15s} [{2:17s}] {3:32s} listing on port {4:6d}".format(device, addr, mac, host, info.port))
                log.write("  -> {0:50s} on {1:15s} [{2:17s}] {3:32s} listing on port {4:6d}\n".format(device, addr, mac, host, info.port))
            else:
                print("  -> {0:50s} on {1:15s} - {3:32s} listing on port {2:6d}".format(device, addr, host, info.port))
                log.write("  -> {0:50s} on {1:15s} - {3:32s} listing on port {2:6d}\n".format(device, addr, host, info.port))
            
            if prop:
                extra = []
                if info.properties:
                    for key, value in info.properties.items():
                        strkey = key.decode("utf-8")
                        if strkey != "":
                            if value != None:
                                strvalue = value.decode("utf-8")
                            else:
                                strvalue = "None"
                            extra.append("         {0:}: {1:}\n".format(strkey, strvalue))

                    print("".join(extra))
                    log.write("".join(extra) + "\n")
                   
        t_end = time.time() + 10
#----------------------------------------------------------------------------------
      
#----------------------------------------------------------------------------------
def get_mac_address(ip_address):
    
    # Ping the IP address
    subprocess.run(["ping", "-c", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Get the ARP table
    arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE).stdout.decode()
  
    mac_address = ""
    for line in arp_output.split("\r\n"):
        if ip_address in line:
            mac_address = line.replace(ip_address, "").strip().replace("-",":")[0:17].strip()
            break
    
    if mac_address != "":
        return mac_address
    else:
        return None
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def scanNetwork(startIP, endIP, startPort, endPort):
    
    global dictPorts
    
    """ Starts a TCP scan on a given IP address range """

    print(F"Starting TCP port scan from {startIP} to {endIP}")
    # Convert IP addresses to integers
    start = list(map(int, startIP.split('.')))
    end = list(map(int, endIP.split('.')))

    csv = open(csvFileName, 'r')
    csvlines = csv.readlines()
    for line in csvlines:
        key,value = line.strip().split(';')
        dictPorts[key] = value[1:-1]
        
    # Generate IP range
    for i in range(start[0], end[0] + 1):
        for j in range(start[1], end[1] + 1):
            for k in range(start[2], end[2] + 1):
                for l in range(start[3], end[3] + 1):
                    ip = f"{i}.{j}.{k}.{l}"
                    if check(ip):
                        tcp_scan(ip, startPort, endPort)
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def scanNetwork(ipalive, startPort, endPort):
    
    global dictPorts
    
    """ Starts a TCP scan on a given IP address range """
    # Convert IP addresses to integers
    csv = open(csvFileName, 'r')
    csvlines = csv.readlines()
    for line in csvlines:
        key,value = line.strip().split(';')
        dictPorts[key] = value[1:-1]
        
    # Generate IP range
    for ip in ipalive:
        tcp_scan(ip, startPort, endPort)
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def tcp_scan(ip, startPort, endPort):

    global dictPorts
    
    print(F"  -> TCP port scan for {ip}")
    cnt = 0
    for port in range(startPort, endPort + 1):
        cnt = cnt + 1
        print(F"     >> Scanning port {cnt}", end="\r")
        try:
            # Create a new socket
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Print if the port is open
            if not tcp.connect_ex((ip, port)):
                if str(port) in dictPorts:
                    print("        Port {0:6d} on {1:15s} open ({2:})".format(port, ip, dictPorts[str(port)]))
                    log.write("Port {0:6d} on {1:15s} open ({2:})\n".format(port, ip, dictPorts[str(port)]))
                else:
                    print("        Port {0:6d} on {1:15s} open".format(port, ip))
                    log.write("Port {0:6d} on {1:15s} open\n".format(port, ip))
                tcp.close()
                log.flush()
                
        except Exception:
            tcp.close()
            pass
#----------------------------------------------------------------------------------
        
#----------------------------------------------------------------------------------
if __name__ == "__main__":
    
    log = open(logFileName, 'w')
    
    # interfaces = netifaces.interfaces()
    interface=netifaces.ifaddresses(netifaces.interfaces()[0])
    mask=interface[netifaces.AF_INET][0]["netmask"].split('.')
    addr=interface[netifaces.AF_INET][0]["addr"].split('.')
    startIP = ""
    endIP   = ""

    if mask[0] == '255':
        startIP = startIP + addr[0]
        endIP   = endIP   + addr[0]
    
        if mask[1] == '255':
            startIP = startIP + '.' + addr[1]
            endIP   = endIP   + '.' + addr[1]
        else:
            startIP = startIP + '.1' 
            endIP   = endIP   + '.254'
        if mask[2] == '255':
            startIP = startIP + '.' + addr[2]
            endIP   = endIP   + '.' + addr[2]
        else:
            startIP = startIP + '.1' 
            endIP   = endIP   + '.254'
        if mask[3] == '255':
            startIP = startIP + '.' + addr[3]
            endIP   = endIP   + '.' + addr[3]
        else:
            startIP = startIP + '.1' 
            endIP   = endIP   + '.254'
    else:
        startIP = "1.1.1.1"
        endIP   = "255.255.255.255"
        
    # Scan the IP range
    if DOPING:
        scan_ip_range(startIP, endIP)
        log.flush()

    if DOMDNS:
        zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        known = [   
                    {"name":"SLEEP PROXY",                                  "service":"_sleep-proxy._udp.local.",       "prop":False}, 
                    # This is a Bonjour Sleep Proxy. 
                    # The idea is that the AppleTV can respond to various network queries for other devices that are currently in low-power mode to lower energy usage. 
                    # For example it could be a Mac offering a shared iTunes library or a shared printer. The AppleTV can then answer network requests for these servers while the Mac is in sleep mode - for example allowing the user to list the shared printers available on the network. However, when the user chooses to print something, the AppleTV will wake up the Mac and transfer the request to it.
                    
                    {"name":"APPLE TV",                                     "service":"_touch-able._tcp.local.",        "prop":False},
                    {"name":"Apple TV2",                                    "service":"_appletv-v2._tcp.local.",        "prop":False},
                    # This is another of the network services that makes the Apple TV Remote work. 
                    # This service concerns device authentication. 
                    # I.e. if you want to for example play a Youtube video on the Apple TV, the Apple TV can require that the device is authenticated before being allowed to do so. 
                    # In practice authentications work by the Apple TV displaying a PIN-code on the TV that the user enters on the iOS device. 
                    # his PIN-code is transferred using the service advertised as "touch-able" to authenticate the device.
                    
                    {"name":"MEDIA REMOTE TV",                              "service":"_mediaremotetv._tcp.local.",     "prop":False},
                    # This is one of the network services that makes the Apple TV Remote work. 
                    # I.e. the app or Control Center built-in feature for remote controlling Apple TV devices from iPhones and iPads. 
                    # This service is advertised on the network via Bonjour to ensure that iOS devices can discover the AppleTV.
                   
                    {"name":"AIRPLAY",                                      "service":"_airplay._tcp.local.",           "prop":False},
                    # This is a Bonjour advertisement for the network service that enables AirPlay of video content.
                    # I.e. this allows iOS devices to discover the Apple TV as a "remote display" that it can display video on.
                   
                    {"name":"COMPANION (AirPlay 2)",                        "service":"_companion-link._tcp.local.",    "prop":False},
                    # This service is seemingly not documented by Apple, but seems involved in making the AirPlay 2 system work.
                   
                    {"name":"RAOP (Remote Audio Output Protocol)",          "service":"_raop._tcp.local.",              "prop":False},
                    # This network service is called Remote Audio Output Protocol.
                    # It is essentially saying that the AppleTV works as an AirPlay audio receiver. 
                    # This Bonjour advertisement allows iOS devices to discover the Apple TV as a "speaker" that you can send audio to.
                    
                    {"name":"AIRPORT",                                      "service":"_airport._tcp.local.",           "prop":False},
                    {"name":"CHROMECAST",                                   "service":"_googlecast._tcp.local.",        "prop":False},
                    {"name":"DEVICE INFO",                                  "service":"_device-info._tcp.local.",       "prop":False},
                    {"name":"HTTP WEB SERVER",                              "service":"_http._tcp.local.",              "prop":False},
                    
                    {"name":"HOMEKIT",                                      "service":"_homekit._tcp.local.",           "prop":False},
                    # This is a network service regarding HomeKit, Apple's system for communicating with and controlling devices in the home. 
                    # Think controllable light bulbs, shades, door bells, whatever. 
                    # The AppleTV works as a proxy in such a setting such that the user can control devices remotely (i.e. while not at home) 
                    # even though the devices might be Bluetooth only and out of range. 
                    # Note that ordinary HomeKit devices on the network advertise as _hap._tcp instead.
                    
                    {"name":"HAP (HomeKit Assecory Protocol)",              "service":"_hap._tcp.local.",               "prop":False},
                    {"name":"ESPHOME",                                      "service":"_esphomelib._tcp.local.",        "prop":False},
                    {"name":"ARDUINO OTA (Over The Air Programming)",       "service":"_arduino._tcp.local.",           "prop":True },
                    {"name":"PRINTER",                                      "service":"_ipp._tcp.local.",               "prop":False},
                    {"name":"ANDROID TV",                                   "service":"_androidtvremote._tcp.local.",   "prop":False},
                    {"name":"AMAZON ECHO",                                  "service":"_amazonecho-remote._tcp.local.", "prop":False},
                    {"name":"WORKSTATION",                                  "service":"_workstation._tcp.local.",       "prop":False},
                    {"name":"AMAZON TV",                                    "service":"_amzn-wplay._tcp.local.",        "prop":False},
                    {"name":"AQARA SETUP",                                  "service":"_aqara-setup._tcp.local.",       "prop":False},
                    {"name":"AQARA",                                        "service":"_aqara._tcp.local.",             "prop":False},
                    {"name":"BOSE",                                         "service":"_bose._tcp.local.",              "prop":False},
                    {"name":"PHILIPS HUE",                                  "service":"_philipshue._tcp.local.",        "prop":False},
                    {"name":"ROKU MEDIA PLAYER",                            "service":"_roku._tcp.local.",              "prop":False},
                    {"name":"ROKU MEDIA PLAYER",                            "service":"_rsp._tcp.local.",               "prop":False},
                    {"name":"SONOS",                                        "service":"_sonos._tcp.local.",             "prop":False},
                    {"name":"SPOTIFY",                                      "service":"_spotify-connect._tcp.local.",   "prop":False},
                    {"name":"TP-LINK",                                      "service":"_tplink._tcp.local.",            "prop":False},
                    {"name":"UBUNTU / RASPBERRY PI ADVERTISEMENT",          "service":"_udisks-ssh._tcp.local.",        "prop":False}
                ]

        for entry in known:
            name       = entry["name"].upper()
            service    = entry["service"].replace(".local.","")
            prop       = entry["prop"]
            print("\nSearching for {0:40s} ({1:})".format(name, service))
            log.write("\nSearching for {0:40s} ({1:})\n".format(name, service))
        
            services = [entry["service"]]
            browser  = ServiceBrowser(zeroconf, services, handlers=[on_service_state_change])
            t_end    = time.time() + 10

            cnt = 0
            while True:
                time.sleep(0.1)
                cnt = cnt + 1
                print("".join(["."] * int(cnt / 3)), end="\r")
                if time.time() >= t_end:
                    break
            log.flush()
            
        zeroconf.close()

    if DOPORTSCAN and DOPING:
        scanNetwork(ipalive, 1, 65535)
    elif DOPORTSCAN and not DOPING:
        scanNetwork(startIP, endIP, 1, 65535)
    
    log.close()
