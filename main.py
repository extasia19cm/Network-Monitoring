import json
import datetime
from scapy.all import sniff, ARP, DNS, DNSQR
from colorama import init, Fore, Style
import socket
import os

init()

# Словарь для хранения подключенных устройств
connected_devices = {}
connected_devices_filename = 'connected_devices.json'
web_search_directory = 'web_search'

# Создание файла connected_devices.json, если его нет
if not os.path.exists(connected_devices_filename):
    with open(connected_devices_filename, 'w') as file:
        json.dump(connected_devices, file)

# Создание папки web_search, если ее нет
if not os.path.exists(web_search_directory):
    os.makedirs(web_search_directory)

# Функция для сохранения данных в JSON файл
def save_to_json(data, filename):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        print(Fore.GREEN + f"Данные успешно сохранены в {filename}" + Style.RESET_ALL)
    except Exception as error:
        print(Fore.RED + f"Ошибка при сохранении в {filename}: {error}" + Style.RESET_ALL)

# Функция для получения имени устройства по IP адресу
def get_device_name(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "unknown"

# Обработчик ARP пакетов
def handle_arp_packet(packet):
    mac_address = packet[ARP].hwsrc
    ip_address = packet[ARP].psrc
    device_name = get_device_name(ip_address)
    
    if mac_address not in connected_devices:
        connected_devices[mac_address] = {'ip': ip_address, 'name': device_name}
        print(Fore.BLUE + f"Найдено новое устройство: {mac_address} -> {ip_address} ({device_name})" + Style.RESET_ALL)
        save_to_json(connected_devices, connected_devices_filename)
    elif connected_devices[mac_address]['ip'] != ip_address or connected_devices[mac_address]['name'] != device_name:
        connected_devices[mac_address] = {'ip': ip_address, 'name': device_name}
        print(Fore.YELLOW + f"Обновлено устройство: {mac_address} -> {ip_address} ({device_name})" + Style.RESET_ALL)
        save_to_json(connected_devices, connected_devices_filename)

# Обработчик DNS пакетов
def handle_dns_packet(packet):
    mac_address = packet.src
    website_visited = packet[DNSQR].qname.decode('utf-8')
    timestamp = datetime.datetime.now().isoformat()
    device_name = get_device_name(packet[DNS].qd.qname.decode('utf-8'))
    
    filename = os.path.join(web_search_directory, f"{device_name}.json")
    
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            web_search_data = json.load(file)
    else:
        web_search_data = []
    
    web_search_data.append({'website': website_visited, 'time': timestamp})
    
    print(Fore.MAGENTA + f"Устройство {device_name} посетило сайт: {website_visited} в {timestamp}" + Style.RESET_ALL)
    save_to_json(web_search_data, filename)

# Функция обратного вызова для обработки пакетов
def packet_callback(packet):
    print(Fore.CYAN + packet.summary() + Style.RESET_ALL)
    try:
        if ARP in packet and packet[ARP].op in (1, 2):
            handle_arp_packet(packet)
        if DNS in packet and packet[DNS].qr == 0:
            handle_dns_packet(packet)
    except Exception as error:
        print(Fore.RED + f"Ошибка при обработке пакета: {error}" + Style.RESET_ALL)

# Запуск прослушивания сетевых пакетов
sniff(prn=packet_callback, store=0)
