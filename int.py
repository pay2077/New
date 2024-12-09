from scapy.all import sniff, IP
from collections import defaultdict
import time

# Налаштування
THRESHOLD = 100  # Порогове значення пакетів від одного джерела за одиницю часу
ALERT_INTERVAL = 60  # Інтервал для перевірки (в секундах)
log_file = "alerts.log"

# Словник для відстеження кількості пакетів від кожного джерела
traffic_counter = defaultdict(int)

def process_packet(packet):
    """Обробка кожного пакету."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        traffic_counter[src_ip] += 1

def analyze_traffic():
    """Аналіз трафіку на наявність аномалій."""
    global traffic_counter
    print("[INFO] Аналіз трафіку...")
    for src_ip, count in traffic_counter.items():
        if count > THRESHOLD:
            alert_message = f"[ALERT] Аномалія: {src_ip} надіслав {count} пакетів за {ALERT_INTERVAL} секунд."
            print(alert_message)
            with open(log_file, "a") as f:
                f.write(alert_message + "\n")
    # Очищення статистики
    traffic_counter.clear()

def main():
    """Головна функція."""
    print("[INFO] Запуск моніторингу трафіку...")
    # Запуск захоплення трафіку
    sniff_thread = sniff(prn=process_packet, store=False, iface="eth0", timeout=ALERT_INTERVAL)

    # Цикл аналізу
    while True:
        time.sleep(ALERT_INTERVAL)
        analyze_traffic()

if __name__ == "__main__":
    main()
