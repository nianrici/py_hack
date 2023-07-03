from scapy.all import *
from prettytable import PrettyTable

'''
Función para mostrar la tabla de direcciones y 
el número de paquetes recibidos por cada una.
'''

def process_packet(packet):
    # Extraemos la dirección de destino del paquete
    dst = packet.dst

    # Actualizamos la tabla con la dirección de destino y el número de paquetes recibidos
    if dst in packet_counts:
        packet_counts[dst] += 1
    else:
        packet_counts[dst] = 1

    # Creamos una lista de tuplas con la información de las direcciones y la cantidad de paquetes recibidos, ordenada por la cantidad de paquetes recibidos
    rows = [(dst, count) for dst, count in packet_counts.items()]
    rows = sorted(rows, key=lambda x: x[1], reverse=True)

    # Creamos la tabla de PrettyTable y la mostramos por pantalla
    table = PrettyTable(["Dirección", "Número de paquetes recibidos"])
    for row in rows:
        table.add_row(row)
    print(table)

packet_counts = {}

# Capturamos los paquetes y llamamos a la función process_packet para procesar cada uno
sniff(prn=process_packet)