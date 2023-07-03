from scapy.all import *
import random
import time

'''
OJO, vas a necesitar permisos de administrador.

Esta función utiliza un modo sigiloso (stealth 
mode) para evitar ser detectado por sistemas de 
seguridad. En lugar de enviar un paquete completo 
TCP (SYN, ACK), envía solo un paquete TCP SYN 
(flags='S') y espera la respuesta. Si no hay 
respuesta, el puerto se considera abierto. Si la 
respuesta tiene el flag 0x12 (SYN, ACK), entonces 
el puerto también se considera abierto y se envía 
un paquete TCP RST (flags='R') para cerrar la 
conexión.

Además, esta función utiliza un puerto de origen 
aleatorio (src_port) para evitar ser identificado 
fácilmente como un escaneo de puertos. También 
incluye un tiempo de espera (timeout) y un retraso 
entre paquetes (delay) para personalizar el escaneo 
y evitar ser detectado por sistemas de seguridad.
'''

def port_scan(ip, port_range=(1, 1024), timeout=1, delay=0.1):
    stealth_mode = True
    src_port = random.randint(1025, 65535)
    open_ports = []

    for dst_port in range(port_range[0], port_range[1]+1):
        stealth_scan = TCP(sport=src_port, dport=dst_port, flags='S')
        response = sr1(IP(dst=ip)/stealth_scan, timeout=timeout, verbose=0)
        time.sleep(delay)

        if not response:
            open_ports.append(dst_port)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            rst_scan = TCP(sport=src_port, dport=dst_port, flags='R')
            send(IP(dst=ip)/rst_scan, verbose=0)
            open_ports.append(dst_port)

    return open_ports

'''
Ejemplo de uso:

ip = "192.168.1.111"
ports = port_scan(ip)
print(f"Los puertos abiertos en {ip} son: {ports}")
'''