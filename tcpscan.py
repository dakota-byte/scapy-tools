r"""
 ______   ______     ______   ______     ______     ______     __   __    
/\__  _\ /\  ___\   /\  == \ /\  ___\   /\  ___\   /\  __ \   /\ "-.\ \   
\/_/\ \/ \ \ \____  \ \  _-/ \ \___  \  \ \ \____  \ \  __ \  \ \ \-.  \  
   \ \_\  \ \_____\  \ \_\    \/\_____\  \ \_____\  \ \_\ \_\  \ \_ \"\_\ 
    \/_/   \/_____/   \/_/     \/_____/   \/_____/   \/_/\/_/   \/_/ \/_/ 
                                                                          
CSE363: Homework 2
By: Dakota Levermann
"""

# Imports
import argparse
from scapy.all import *
load_layer("tls")
import socket
import ssl

# Default ports to scan on when not specified
default_ports = [21, 22, 23, 25, 80, 110,
                 143, 443, 587, 853, 993,
                 3389, 8080]

# Convert a string "X-Y" to a list [X..Y]
def expand_ports(port_range):
    if port_range == None:
        return None

    if "-" in port_range:
        parts = port_range.split("-")
        begin = int(parts[0])
        end = int(parts[1])+1
        return list(range(begin, end))
    return [int(port_range)]

# argparse
parser = argparse.ArgumentParser(prog="tcpscan.py", add_help=False)
parser.add_argument('-p', '--port_range')
parser.add_argument('target', nargs='*')
args = parser.parse_args()

# begin tcp scan
port_range = expand_ports(args.port_range) or default_ports
target = args.target[0]

### HELPER FUNCTIONS ###
GET_REQUEST = "GET / HTTP/1.0\r\nHost: {target}\r\n\r\n"
GENERIC_REQUEST = "\r\n\r\n\r\n\r\n"

def hexify(data):
    '''Print characters out in a nice way'''
    # the -5 gets rid of newlines and other carriage return stuff
    output = ''.join(chr(b) if chr(b) in string.printable[:-5] else '.' for b in data)  
    return output

def probe_TLS(target, port):
    '''Determine if target is running on TLS or not'''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=target)
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except:
        return False

def probe_serv_resp_tcp(target, port):
    '''Probe for a server-initiated banner over TCP'''
    try:
        probe_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_1.settimeout(3)
        probe_1.connect((target, port))
        response = probe_1.recv(1024)
        return response
    except Exception as e:
        pass #return f"Failed: {e}"

def probe_serv_resp_tls(target, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                #ssock.send(GET_REQUEST.encode()) # DO NOT SEND GET 
                response = ssock.recv(1024)
                return response
    except Exception as e:
        pass #return f"Failed: {e}"

def probe_http(target, port):
    '''Try to get a response from a GET request in clear'''
    try:
        probe_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_1.settimeout(3)
        probe_1.connect((target, port))
        probe_1.send(GET_REQUEST.encode())
        response = probe_1.recv(1024)
        return response[:1024]
    except Exception as e:
        pass #return f"Failed: {e}"

def probe_https(target, port):
    '''Connect to TLS and send a GET request, hope for response'''
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.send(GET_REQUEST.encode())
                response = ssock.recv(1024)
                return response
    except Exception as e:
        pass #return f"Failed: {e}"

def probe_gen_tls(target, port):
    '''Connect to TLS and send generic lines, hope for response'''
    no_resp = False
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.send(GENERIC_REQUEST.encode())
                # if I made it this far, the below might error
                no_resp = True
                response = ssock.recv(1024)
                return response
    except Exception as e:
        if no_resp:
            return True
        pass #return f"Failed: {e}"


def probe_gen_tcp(target, port):
    '''Get response from generic lines sent in clear'''
    no_resp = False
    try:
        probe_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_1.settimeout(3)
        probe_1.connect((target, port))
        probe_1.send(GENERIC_REQUEST.encode())
        no_resp = True #In case exception gets thrown by following line
        response = probe_1.recv(1024)
        return response[:1024]
    except Exception as e:
        if no_resp:
            return True
        return f"Failed: {e}"


print(f'Scanning {target} on {len(port_range)} port(s)\n')

closed_ports = 0
for port in port_range:
    # send TCP SYN request
    response = sr1(IP(dst=target)/TCP(sport=12345, dport=port,flags="S"), verbose=0, timeout=3)
    
    # well this is a TCP scan so...
    if (not response or TCP not in response):
        #print(f"Unexpected error with port {port}")
        closed_ports += 1
        continue

    # get the TCP flags
    tcp_flags = response[TCP].fields['flags']

    # we expect a SYN-ACK back, otherwise it's probably closed ("RA", RST)
    # getting a "SYN" back is also open apparently?
    if (tcp_flags != "SA" or "S" not in tcp_flags):
        closed_ports += 1
        continue

    # output Host
    print(f"Host: {target}:{port}")

    # first, we check to see if the host is using TLS
    TLS_response = probe_TLS(target, port)

    # First, check to see if the server returns a banner on TLS
    type_2 = probe_serv_resp_tls(target, port)
    if type_2 and TLS_response:
        print(f"Type: (2) TLS server-initiated")
        print(f"Response: {hexify(type_2)}\n")
        continue

    # If not, check to see if server returns data over TCP
    type_1 = probe_serv_resp_tcp(target, port) 
    if type_1 and not TLS_response:
        print(f"Type: (1) TCP server-initiated")
        print(f"Response: {hexify(type_1)}\n")
        continue

    # If not, try to send a GET over HTTPS
    type_4 = probe_https(target, port)
    if type_4 and TLS_response:
        print(f"Type: (4) HTTPS Server")
        print(f"Response: {hexify(type_4)}\n")
        continue

    # If not, try to send a GET over HTTP
    type_3 = probe_http(target, port)
    if type_3 and not TLS_response:
        print(f"Type: (3) HTTP Server")
        print(f"Response: {hexify(type_3)}\n")
        continue

    # If not, try to send generic lines over TLS
    type_6 = probe_gen_tls(target, port)
    if type_6 and TLS_response:
        print(f"Type: (6) Generic TLS Server")
        if type_6 == True:
            print(f"Response:\n") # no response
        else:
            print(f"Response: {hexify(type_6)}\n")
        continue

    # If not, try to send generic lines over TCP
    type_5 = probe_gen_tcp(target, port)
    if type_5 and not TLS_response:
        print(f"Type: (5) Generic TCP Server")
        if type_5 == True:
            print("Response:\n") # No response
        else:
            print(f"Response: {hexify(type_5)}\n")
        continue

    print(f"Type: (0) N/A (ERROR)")


print(f"\nFINSHED: {closed_ports} port(s) were closed.")
