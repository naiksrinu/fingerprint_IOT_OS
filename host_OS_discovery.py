#
# __date__ = 16 / 12 / 2016
# __author__ = '0xN41K'
#
# Description = " Understand the target OS based on TTL Value " 
# Technical   = " This script takes help of SCAPY module and sends the L3 frame with ICMP Request"
# 

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import string
import sys, os

def OSdiscovery(target):
  try:
      ans,unans=sr(IP(dst=target[1])/ICMP(), inter=0.05,timeout=0.5)
      for s,r in ans:
          print  "#"*5 + " Response Frame " + "#"*5
          print  ans , r
          #print "\n ------ Hexdump ------"
          #print hexdump(r)        
          print  "#"*5 + " @@@@@@@@@@@@@@@ " + "#"*5+ "\n"
          print '\033[1m'
          if r.ttl ==  62:
              print "{0} is Alive :: Guessing to be a Mobile Hotspot(TTL = {1})".format(str(r.src), str(r.ttl))
          elif r.ttl ==  64:
              print "{0} is Alive :: Guessing to be a Linux Box(TTL = {1})".format(str(r.src), str(r.ttl))
          else:
              print "{0} is Alive :: Guessing to be a Windows Machine(TTL = {1})".format(str(r.src), str(r.ttl))
  except Exception, e:
      print e

      
def NetworkDiscovery(target):
  cmd_net = 'nmap -sC -sV -p- -Pn '+ target +' -o ./network_nmap.log'
  os.system(cmd_net)
  
def main():
        target = sys.argv
        if len(sys.argv) < 2:
                print "*" * 15
                print " >>> python " + sys.argv[0]+ " <TargetIP> \n"
                print "*" * 15
                sys.exit(1)
        OSdiscovery(target)
        print '\033[0;0m'
        print "\n"+"#" *5 + "  Th4nk Y0u  " +"#"*5

if __name__ == '__main__':
  main()

