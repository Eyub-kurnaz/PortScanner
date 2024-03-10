from multiprocessing import Pool, Manager
from scapy.all import *
import time
import os
import nmap

#-O Scan
def detect_os(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-O')
    os_info_list = nm[target_ip]['osmatch']
    if os_info_list:
        for os_info in os_info_list:
            name = os_info['name']
            accuracy = os_info['accuracy']
            info=f"Name: {name}, Accuracy: {accuracy}"
    else:
        print("İşletim sistemi bilgisi bulunamadı.")
    return info


# -sT Scan
def scan_tcp_t(port, target_ip, open_ports):
    print(f"Taranıyor: {port}")
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=0.2, verbose=0)
    if response is not None and response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            print(f"Port {port} açık! SYN/ACK alındı.")
            open_ports.append(port)
            ack_packet = IP(dst=target_ip) / TCP(dport=port, flags="A", seq=response[TCP].ack,ack=response[TCP].seq + 1)
            send(ack_packet)
            time.sleep(0.1)
            rst_ack_packet = IP(dst=target_ip) / TCP(dport=port, flags="RA", seq=1, ack=response[TCP].seq + 1)
            send(rst_ack_packet)

        elif response[TCP].flags == 0x14:
            print(f"Port {port} kapalı. RST alındı.")
        else:
            print(f"Port {port} için bilinmeyen bir cevap alındı. Flag: {hex(response[TCP].flags)}")
            response.show()
    else:
        print(f"Port {port} için cevap alınamadı.")


# -sS Scan
def scan_syn_tcp(port, target_ip, open_ports):
    print(f"Taranıyor: {port}")
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=0.2, verbose=0)
    if response is not None and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN/ACK
            print(f"Port {port} açık! SYN/ACK alındı.")
            ack_packet = IP(dst=target_ip) / TCP(dport=port, flags="R", seq=1)
            send(ack_packet)
            open_ports.append(port)
        elif response[TCP].flags == 0x14:  # RST
            print(f"Port {port} kapalı. RST alındı.")
        else:
            print(f"Port {port} için bilinmeyen bir cevap alındı. Flag: {hex(response[TCP].flags)}")
            response.show()
    else:
        print(f"Port {port} için cevap alınamadı.")

#-sV Scan
def scan_service(args):
    port, target_ip, open_ports = args
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments=f'-p {port} -sV')
    name = nm[target_ip]['tcp'][port]['name']
    product = nm[target_ip]['tcp'][port]['product']
    version = nm[target_ip]['tcp'][port]['version']
    print(f"Port: {port} | Name: {name} | Product: {product} | Version: {version}")


open_port_list_for_service = []
open_port_list_for_syn = []
open_port_list_for_tcp = []


def main():
    cpu_count = os.cpu_count()
    target_ip = "104.247.168.18"
    port_range = "1-1000"
    scan_type = "-sV"
    start_port = int(port_range.split("-")[0])
    end_port = int(port_range.split("-")[1])

    if scan_type == "-sT":
        print("-sT Taraması yapılıyor..")
        with Manager() as manager:
            global open_port_list_for_tcp
            open_ports = manager.list()
            num_threads = cpu_count * 4
            with Pool(num_threads) as pool:
                pool.starmap(scan_tcp_t, [(port, target_ip, open_ports) for port in range(start_port, end_port + 1)])
            print("Açık portlar:", open_ports)
            open_port_list_for_tcp = list(open_ports)

    if scan_type == "-sS":
        print("-sS taraması yapılıyor..")
        with Manager() as manager:
            global open_port_list_for_syn
            open_ports = manager.list()
            num_threads = cpu_count * 4
            with Pool(num_threads) as pool:
                pool.starmap(scan_syn_tcp, [(port, target_ip, open_ports) for port in range(start_port, end_port + 1)])
            print("Açık portlar:", open_ports)
            open_port_list_for_syn = list(open_ports)

    if scan_type == "-sV":
        print("-sV taraması yapılıyor..")
        with Manager() as manager:
            global open_port_list_for_service
            open_ports = manager.list()
            num_threads = cpu_count * 4
            with Pool(num_threads) as pool:
                pool.starmap(scan_syn_tcp, [(port, target_ip, open_ports) for port in range(start_port, end_port + 1)])
            print("Açık portlar:", open_ports)
            open_port_list_for_service = list(open_ports)
        if not open_port_list_for_service:
            print("Açık port yok.")
        else:
            print("Açık portlar bulundu servis bilgisi işleniyor..")
            with Manager() as manager:
                num_threads = len(open_port_list_for_service)
                open_ports = manager.list(open_port_list_for_service)
                with Pool(num_threads) as pool:
                    pool.map(scan_service, [(port, target_ip, open_ports) for port in open_ports])
    system_info = detect_os(target_ip)
    print("System info:", system_info)


if __name__ == "__main__":
    main()







































