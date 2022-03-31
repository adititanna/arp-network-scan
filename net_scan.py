#!/usr/bin/env python

# trying to make something similar to netdiscover - which gives the ip, mac and hostname for all devices on the same network
# eg. netdiscover -r 192.168.100.1/24

# scapy.all.arping(ip) helps to scan IP and return the ip and mac address. If we want to try building our own:
#     1. Create arp request directed to broadcast MAC asking for IP
#             a. Use ARP to ask who has target IP
#             b. Set destination MAC to broadcast MAC
#     2. Send packet and receive response
#     3. Parse the response and print result

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # create an ARP packet
    # print(arp_request.summary())  # default prints "ARP who has 0.0.0.0 says 192.168.100.130"
    # scapy.ls(scapy.ARP())   # displays the various options/variables in scapy.ARP()
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Create an Ethernet frame to which we have to append our ARP request
    # print(broadcast.summary())  # displays "00:0c:29:94:b5:4f > ff:ff:ff:ff:ff:ff (0x9000)"
    # scapy.ls(scapy.Ether())
    # broadcast.show()
    arp_request_broadcast = broadcast / arp_request  # Combining the 2 packets
    # print(arp_request_broadcast.summary())
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # to send the packet - srp used for custom Ether send/receive, sr() used for default send receive
    # returns a list of the answerd and unanswered packets amd timeout 1 second and verbose False doesn't display the additional info
    # print(answered_list.summary())

    clients_list = []
    for element in answered_list:  # element contains (packet, answer)
        # print(element[1].show())
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
