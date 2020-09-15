#!/usr/bin/env python3

from pwn import *

p = remote('crypto.chal.csaw.io', 5001)
p.recvline()
string = ""
i = 0
while True:
    line = p.recvline()
    if b'plaintext' not in line: # check whether we don't have the same response
        print(line)
        break
    payload = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    p.sendline(payload)
    p.recvuntil('Ciphertext is:  ')
    cipher = p.recvline().strip()
    print(cipher)
    p.recvline()
    if cipher[:32] == cipher[32:64]:
        p.sendline('ECB')
        string += '0'
    else:
        p.sendline('CBC')
        string += '1'
    i += 1
    if i == 176: break
    print("Done " + str(i))

p.interactive()
print(string)
# 01100110011011000110000101100111011110110100010101000011010000100101111101110010011001010100000001101100011011000111100101011111011100110101010101100011011010110010010001111101
print(int(string, 2))
print(hex(int(string, 2)))
# 0x666c61677b4543425f7265406c6c795f7355636b247d
print(bytes.fromhex(hex(int(string, 2))[2:]))
# b'flag{ECB_re@lly_sUck$}'
