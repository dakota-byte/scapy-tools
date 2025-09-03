# Imports
from scapy.all import *
from scapy.layers.http import *
from scapy.layers import http
load_layer("tls")
from datetime import datetime

# argparse
import argparse
parser = argparse.ArgumentParser(prog="capture.py",
                                 add_help=False)
parser.add_argument('-i', '--interface')
parser.add_argument('-r', '--tracefile')
parser.add_argument('expression', nargs='*') 

args = parser.parse_args()
interface = args.interface or conf.iface
tracefile = args.tracefile
expression = " ".join(args.expression)

def format_timestamp(timestamp):
    if tracefile:
        timestamp = int(timestamp)
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

def get_servername(msg_text):
    # Takes the giant TLS.msg field and parses it for the server name
    if "servernames=[" not in msg_text:
        return None
    start = msg_text.index("servernames=[") # 13 chars long
    end = msg_text.find(" ", start+13)

    field = msg_text[start+13:end-1]
    servername = field[2:len(field)-1] # get rid of the surrounding b''
    return servername


def print_format(packet):

    # Nonstandard HTTP
    if (IP in packet) and (TCP in packet) and (Raw in packet):
        raw_data = str(packet[Raw].load.decode())
        method = ""
        if (raw_data[0:3] == "GET"):
            method = "GET"
        elif (raw_data[0:4] == "POST"):
            method = "POST"
        else:
            return

        path_start = raw_data.find(" ")
        path_end = raw_data.find(" ", path_start+1)
        path = raw_data[path_start+1:path_end]

        host_start = raw_data.find("Host: ")
        host_end = raw_data.find("\r\n", host_start+6)
        host = raw_data[host_start+6:host_end]

        print(format_timestamp(packet.time), "HTTP", str(packet[IP].src)+":"+str(packet[IP].sport),
              "->", str(packet[IP].dst)+":"+str(packet[IP].dport), host, method, path, sep=" ")

    # HTTP Traffic
    if (IP in packet) and (TCP in packet) and (HTTP in packet):
        if (HTTPRequest in packet):
            req = packet[HTTPRequest]
            print(format_timestamp(packet.time), "HTTP", str(packet[IP].src)+":"+str(packet[IP].sport),
              "->", str(packet[IP].dst)+":"+str(packet[IP].dport), req.Host.decode(),
              req.Method.decode(), req.Path.decode(), sep=" ")
        elif (Raw in packet and packet[IP].src == scapy.all.conf.iface.ip):
            pass #print("Scapy did not detect a HTTP Request")
            
    # DNS Traffic
    if (IP in packet) and (UDP in packet) and (DNS in packet) and (DNSQR in packet):
        if (packet[DNSQR].qtype != 1):
            return
        
        print(format_timestamp(packet.time), "DNS", str(packet[IP].src)+":"+str(packet[IP].sport),
              "->", str(packet[IP].dst)+":"+str(packet[IP].dport), packet[DNSQR].qname.decode(), sep=" ")

    # TLS Traffic
    if (TLS in packet) and (TLSClientHello in packet) and (TLS_Ext_ServerName in packet):
        if packet[TLS].type != 22:
            return
        servername = get_servername(str(packet[TLS].msg))
        
        print(format_timestamp(packet.time), "TLS", str(packet[IP].src)+":"+str(packet[IP].sport),
          "->", str(packet[IP].dst)+":"+str(packet[IP].dport), servername, sep=" ")

# now do the thing
if tracefile:
    packets = sniff(offline=tracefile)
    for packet in packets:
        print_format(packet)
else:
    print("listening on " + interface + " with filter: " + expression)
    sniff(iface=interface, filter=expression, prn=print_format)
