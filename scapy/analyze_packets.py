from scapy.all import *

'''
OJO, necesitarás permisos de administrador.

Este script utiliza la función sniff de Scapy 
para capturar el tráfico en tiempo real y la 
función analyze_packet como callback para 
analizar cada paquete capturado.
IRL el campo "malicious_string" se debería 
reemplazar por codigo malicioso real para ser 
detectado.

'''

def analyze_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if "malicious_string" in payload:
            print("Paquete malicioso detectado:")
            print(packet.show())

sniff(prn=analyze_packet, filter="tcp")