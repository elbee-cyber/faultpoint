from pwn import *

exe = ELF('./malloc_demo')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('addr', 1337)
    return r


io = conn()
index = 0


def malloc(s):
    global index
    io.sendlineafter('>> ', '1')
    io.sendlineafter('>> ', str(s))
    ret = index
    index += 1
    return ret


def read(i):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('>> ', str(i))
    return io.readuntil("\n")[1:-1]

def edit(i, data):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('>> ', str(i))
    io.sendafter('>> ', data)


def free(i):
    global index
    io.sendlineafter('>> ', '4')
    io.sendlineafter('>> ', str(i))

def main():

    # There are 2 ways to solve this, can you find them all?
    # Example usuage, allocate 0x20 chunk, edit, free
    chunk_A = malloc(0x18)
    edit(chunk_A, p64(0xdeadbeef))
    free(chunk_A)

    io.interactive()


if __name__ == '__main__':
    main()
