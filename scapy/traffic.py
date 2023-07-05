from scapy.all import *
from rich.console import Console
from rich.table import Table
import socket
import signal

'''
Función para mostrar la tabla de direcciones y 
el número de paquetes recibidos por cada una.
'''
console = Console()


def get_domain(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ""

def process_packet(packet):
    # Extraemos la dirección de destino y la dirección IP asociada del paquete
    dst = packet.dst
    src_mac = packet.src
    src_ip = packet.getlayer(IP).src if packet.haslayer(IP) else ""
    dst_ip = packet.getlayer(IP).dst if packet.haslayer(IP) else ""
    src_domain = get_domain(src_ip) if src_ip and not src_ip.startswith('192.168.') else ""
    dst_domain = get_domain(dst_ip) if dst_ip and not dst_ip.startswith('192.168.') else ""

    # Actualizamos la tabla con la dirección de destino, la dirección IP asociada y el número de paquetes recibidos
    if dst in packet_counts:
        packet_counts[dst]["count"] += 1
    else:
        packet_counts[dst] = {"count": 1, "src_mac": src_mac, "src_ip": src_ip, "dst_ip": dst_ip, "src_domain": src_domain, "dst_domain": dst_domain}

    # Creamos una lista de tuplas con la información de las direcciones, la dirección IP asociada y la cantidad de paquetes recibidos, ordenada por la cantidad de paquetes recibidos
    rows = [(dst, count_info["src_mac"], count_info["src_ip"], count_info["dst_ip"], count_info["src_domain"], count_info["dst_domain"], count_info["count"]) for dst, count_info in packet_counts.items()]
    rows = sorted(rows, key=lambda x: x[6], reverse=True)

    # Creamos la tabla con la librería rich
    table = Table(title="Tabla de direcciones y número de paquetes recibidos")
    table.add_column("Dirección", style="cyan")
    table.add_column("MAC de origen", style="magenta")
    table.add_column("Dirección IP de origen", style="magenta")
    table.add_column("Dirección IP de destino", style="green")
    table.add_column("Dominio de origen", style="magenta")
    table.add_column("Dominio de destino", style="green")
    table.add_column("Número de paquetes recibidos", style="red")
    for row in rows:
        table.add_row(row[0], row[1], row[2], row[3], row[4], row[5], str(row[6]))
    
    # Limpiamos la consola antes de imprimir la nueva tabla
    console.clear()

    # Mostramos la tabla usando la clase Console
    console.print(table)

def stop_capture(signal, frame):
    # Mostramos la última tabla antes de detener el script
    console.clear()
    console.print("Capture stopped.")
    
    rows = [(dst, count_info["src_mac"], count_info["src_ip"], count_info["dst_ip"], count_info["src_domain"], count_info["dst_domain"], count_info["count"]) for dst, count_info in packet_counts.items()]
    rows = sorted(rows, key=lambda x: x[6], reverse=True)

    table = Table(title="Tabla de direcciones y número de paquetes recibidos")
    table.add_column("Dirección", style="cyan")
    table.add_column("MAC de origen", style="magenta")
    table.add_column("Dirección IP de origen", style="magenta")
    table.add_column("Dirección IP de destino", style="green")
    table.add_column("Dominio de origen", style="magenta")
    table.add_column("Dominio de destino", style="green")
    table.add_column("Número de paquetes recibidos", style="red")
    for row in rows:
        table.add_row(row[0], row[1], row[2], row[3], row[4], row[5], str(row[6]))
    
    # Mostramos la tabla usando la clase Console
    console.print(table)
    sys.exit(0)

packet_counts = {}

# Capturamos los paquetes y llamamos a la función process_packet para procesar cada uno
signal.signal(signal.SIGINT, stop_capture)

sniff(prn=process_packet)