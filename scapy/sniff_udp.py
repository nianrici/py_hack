from scapy.all import *

'''
Función que obtiene una lista de las interfaces 
de red disponibles y le pide al usuario que 
seleccione la interfaz que desea utilizar. La 
función devuelve el nombre de la interfaz 
seleccionada, o None si la interfaz seleccionada 
no está disponible.
OJO, necesitarás permisos de administrador.
'''

def obtener_interfaz_red():
    interfaces = get_if_list()
    print("Interfaces de red disponibles: ", interfaces)
    interfaz_seleccionada = input("Por favor, seleccione la interfaz que desea utilizar: ")
    if interfaz_seleccionada not in interfaces:
        print("La interfaz seleccionada no está disponible.")
        return None
    else:
        return interfaz_seleccionada

'''
Función que utiliza la interfaz seleccionada para
 capturar los primeros 100 paquetes UDP que se 
 encuentran en la red. Los paquetes se filtran 
 utilizando el protocolo UDP y se imprimen en la 
 pantalla utilizando la función summary().
'''

def capturar_paquetes_udp(interfaz):
    print("Comenzando a capturar paquetes UDP...")
    paquetes = sniff(iface=interfaz, filter="udp", count=100)
    print("Se han capturado los siguientes paquetes UDP:")
    for paquete in paquetes:
        print(paquete.summary())

interfaz = obtener_interfaz_red()
if interfaz is not None:
    capturar_paquetes_udp(interfaz)