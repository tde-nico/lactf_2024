from hashlib import sha256

b = [69, 70, -81, -117, -10, 109, 15, 29, 19, 113, 61, -123, -39, 82, -11, -34, 104, -98, -111, 9, 43, 35, -19, 22, 52, -55, -124, -45, -72, -23, 96, -77]
b = bytes([i if i >= 0 else (i + 256) for i in b])

'''
history = [
	0, # 1
	1, # 1
	4, 4, 4, 4,
	4, 4, 4, 4,
	6, # 1
	0, # 2
	2, # 1
	3,
	5,
]
'''

for i in range(256):
	exploit = bin(i)[2:].encode().rjust(8, b'0')
	exploit = b''.join([b'd' if i == 48 else b'p' for i in exploit])

	d = sha256(exploit).digest()
	#print(b.hex(), d.hex(), exploit)
	if d == b:
		print(i)
		print(exploit)
		break

#  lactf{the_graphics_got_a_lot_worse_from_what_i_remembered}
