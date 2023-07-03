from pwn import *

'''
Función para conectarse a un pc remoto mediante ssh
y listar los procesos que están corriendo.
'''

def listar_procesos_remotos(ip, usuario, contrasena):
    conexion = ssh(usuario, ip, password=contrasena)
    procesos = conexion.process('ps aux').recvall().decode()
    procesos_lista = procesos.split('\n')
    for proceso in procesos_lista:
        print(f'[+] {proceso}')

    conexion.close()

'''
Función para listar los puertos abiertos en el sistema.
'''

def listar_puertos_abiertos():
    puertos = process('netstat -ltnp').recvall().decode()
    puertos_lista = puertos.split('\n')
    for puerto in puertos_lista:
        print(f'[+] {puerto}')