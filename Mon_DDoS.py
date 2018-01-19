########################################################################################################################### 
#This code aims for Detecting DoS attacks by capturing the packets in real time. Protocols compatible with this program are #IP,ICMP,ARP .This was made possible because of an excellent library Scapy.This Code is just for Educational purposes #only.The main aim of this program is to make a realization for user to understand about protocols in depths. For any #suggestions feel free to contact offpy0987@gmail.com.
###########################################################################################################################

from scapy.all import *
import os
import sys
def main():
     global sb, counter, l
     counter  = 0
     l = dict()
     print"                    ______________________________                   "
     print"                   |   ___ ___  ___   ____        |"
     print"------------------|||  | ||__  |__   |   |  \  / |||-----------------"
     print"------------------|||  | ||    |     |___|   \ / |||-----------------"
     print"------------------|||  | ||    |     |        /  |||-----------------"
     print"------------------|||  |_||    |     |       /   |||-----------------"
     print"                   |______________________________|"
     print"                                                                     "
     intf = raw_input("please enter the INTERFACE:")
     sb = sniff(iface = str(intf), prn = analysis, store = 0)
def analysis(pkt):
 global counter, l
 if IP in pkt:
  src = pkt[IP].src
  dst = pkt[IP].dst
  print"#######IP PACKET#NO.    "+str(counter)
  print"**"+str(src)+"-------------->"+str(dst)+"**"
  stream = src + ":" + dst
  if l.has_key(stream):
    l[stream] = l[stream] + 1
    print l[stream]
    if l[stream] > 1000: #change this value according to need.
      print "UNDER DDOS ATTACK!!"
  else:
    l[stream] = 1
 if ARP in pkt: 
   psrc = pkt[ARP].psrc
   pdst = pkt[ARP].pdst
   print"#######ARP PACKET#NO.   "+str(counter)
   print"**"+str(psrc)+"-------------->"+str(pdst)+"**"
   
 if ICMP in pkt: 
   print"#######ARP PACKET#NO.  "+str(counter)
   print"*******-------------->*********"
 counter += 1
   
   
if __name__ =="__main__":
  main()
