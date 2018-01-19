############################################################################################################################
#This code aims for Detecting DoS attacks by capturing the packets in real time.This was made possible because of an #excellent library Scapy.This Code is just for Educational purposes only.The main aim of this program is to make a #realization for user to understand about protocols in depths. For any suggestions feel free to contact offpy0987@gmail.com.
#The Authors of this code are Satyam Dubey and Yash Bharadwaj
###########################################################################################################################

from scapy.all import *
import netifaces
import os
def sniffer():
  global count
  count = 0
  c = sniff(iface = intf, store = 0 , prn = detect)
def detect(packet):
  global count , mac, ip
  if ARP in packet:
   count += 1
   print "PACKET FOUND NO."+str(count)
   if packet[ARP].op == 2:
     if packet[ARP].hwsrc == str(mac) and packet[ARP].psrc == str(ip):
      print "[+]all is going well"
     else:
      print "[+]ARP attack is being performed by " + str(packet[ARP].hwsrc) +" and "+ str(packet[ARP].psrc) + " ."
def main():
     global intf , mac , ip
     print"                    ______________________________                   "
     print"                   |   ___ ___  ___   ____        |"
     print"------------------|||  | ||__  |__   |   |  \  / |||-----------------"
     print"------------------|||  | ||    |     |___|   \ / |||-----------------"
     print"------------------|||  | ||    |     |        /  |||-----------------"
     print"------------------|||  |_||    |     |       /   |||-----------------"
     print"                   |______________________________|"
     print"                                                                     "
     intf = str(raw_input("[+]please enter the INTERFACE : ")) 
     mac = open('/sys/class/net/' + str(intf) +'/address').readline().split('\n')[0]
     ip1 = subprocess.Popen(["hostname -I"], stdout=subprocess.PIPE, shell=True).communicate()[0]
     ip2 = str(ip1).split(" ")
  main()
     ip = ip2[0]
     sniffer()
if __name__ == "__main__":

    
 
  

