import socket

p = IP(src='1.1.1.1', dst='2.2.2.2')
p /= TCP(sport=45012, dport=80)
p /= Raw('testdata')
p = IP(raw(p))
p

sa = SecurityAssociation(ESP, spi=0x222,
                         crypt_algo='NULL', crypt_key=None,
                         
                         auth_algo='NULL', auth_key=None)

e = sa.encrypt(p)
e

assert(isinstance(e, IP))
assert(e.src == '1.1.1.1' and e.dst == '2.2.2.2')
assert(e.chksum != p.chksum)
assert(e.proto == socket.IPPROTO_ESP)
assert(e.haslayer(ESP))
assert(not e.haslayer(TCP))
assert(e[ESP].spi == sa.spi)
assert(b'testdata' in e[ESP].data)

d = sa.decrypt(e)
d