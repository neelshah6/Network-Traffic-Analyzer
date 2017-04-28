
from scapy.all import *
import pygeoip
import dpkt
import socket
import sys
import os

def inet_to_str(inet):

    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def extract_ips(capture):

    pcap = rdpcap(capture)
    ips = set([(p[IP].fields['src']) for p in pcap if p.haslayer(IP) == 1])
    return ips

def extract_location(ip):

    gi = pygeoip.GeoIP('GeoLiteCity.dat')
    results = gi.record_by_addr(ip)
    required_keys = ['city', 'country_name', 'time_zone', 'latitude', 'longitude', 'postal_code']
    print '\n\n\t\tThe location for the IP address', ip, 'is :'

    if results:
        for keys in results:
            if keys in required_keys:
                print '\t\t', keys, '=', results[keys], '\n'

def black_list_url():

    black_list_url = ['google.com/']
    f = open('urls_test.pcap')
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        tcp = ip.data

        if ip.p == dpkt.ip.IP_PROTO_TCP:
            if tcp.dport == 80:
                try:
                    http = dpkt.http.Request(tcp.data)
                    #count += 1
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue
                url = http.headers['host'] + http.uri

                if url in black_list_url:
                    print url
                    print inet_to_str(ip.src)

def main():
    print "/t/tHow would you like to capture the traffic today?/n"
    ans = raw_input("/t/tEnter 1 for previously captured PCAP or 2 for capturing it live!!/n")
    print "you entered:" + ans
    if ans == '2':
        os.system("tshark -i 1 -w /tmp/live.pcap -a duration:30")
        ip_list = extract_ips("/tmp/live.pcap")
    if ans == '1':
        ip_list = extract_ips("urls_test.pcap")
    else:
        print "Invalid input"
    print "Choose the options accordingly"
    Choice = raw_input("Enter 1 for list of IP address in the pcap file \n Enter 2 for the location of the IP address \n Enter 3 to find out the IP address of the user that uses the blacklisted URl")
    print 'you entered' + Choice

    if Choice == '1':
        print '\n\t\tIP addresses found in the Pcap file are:\n'
        for ip in ip_list:
            print '\t\t', ip
    if Choice == '2':
        for ip in ip_list:
            extract_location(ip)
    if Choice == '3':
        black_list_url()
    else:
        print "invalid input"

if __name__ == "__main__":
    main()