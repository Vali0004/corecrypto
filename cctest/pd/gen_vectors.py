# pd interim LLM-written test tooling, experimental, see README.md
# writes pd_vectors.h: rfc/fips/sp vectors plus reference vectors from python's cryptography as an independent oracle
import hashlib, hmac, os, random, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, cmac, keywrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, Mode, CounterLocation
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES, Blowfish, CAST5

rnd = random.Random(20261028)
def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))

out = []
def arr(name, b):
    out.append('static const uint8_t %s[%d] = {%s};' % (name, max(len(b), 1), ','.join(str(x) for x in b) or '0'))

recs = {}
def rec(kind, fields):
    recs.setdefault(kind, []).append(fields)

n = 0
def blob(b):
    global n
    n += 1
    nm = 'v%d' % n
    arr(nm, b)
    return '%s, %d' % (nm, len(b))

# spec vectors, checked against the oracle before use
assert hashlib.md5(b'abc').hexdigest() == '900150983cd24fb0d6963f7d28e17f72'               # rfc 1321 a.5
assert hashlib.sha256(b'abc').hexdigest().startswith('ba7816bf8f01cfea')                    # fips 180-4 example
k = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
p = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
c = Cipher(algorithms.AES(k), modes.ECB()).encryptor().update(p)
assert c.hex() == '3ad77bb40d7a3660a89ecaf32466ef97'                                         # sp 800-38a f.1.1
assert Cipher(algorithms.AES(k), modes.CBC(bytes(range(16)))).encryptor().update(p).hex() == '7649abac8119b246cee98e9b12e9197d'  # sp 800-38a f.2.1

dig = {'md5': 'di_md5', 'sha1': 'di_sha1', 'sha224': 'di_sha224', 'sha256': 'di_sha256',
       'sha384': 'di_sha384', 'sha512': 'di_sha512', 'ripemd160': 'di_rmd160', 'md4': 'di_md4'}
def H(name, data):
    if name == 'md4':
        return None
    return hashlib.new(name, data).digest()

for name, di in dig.items():
    for L in [0, 1, 3, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 1000, 4097]:
        m = rb(L)
        d = H(name, m)
        if d is None: continue
        rec('digest', '{ %s, %s, %s, "%s/%d" }' % (di, blob(m), blob(d), name, L))
# md4 from rfc 1320 a.5
for m, h in [(b'', '31d6cfe0d16ae931b73c59d7e0c089c0'), (b'a', 'bde52cb31de33e46245e05fbdbd6fb24'), (b'abc', 'a448017aaf21d8525fc10ae87aa6729d'),
             (b'message digest', 'd9130a8164549fe818874806e1c7014b'), (b'12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'e33b4ddc9c38f2199c3e7b164fcc0536')]:
    rec('digest', '{ di_md4, %s, %s, "md4 rfc1320" }' % (blob(m), blob(bytes.fromhex(h))))
# md2 from rfc 1319 a.5
for m, h in [(b'', '8350e5a3e24c153df2275c9f80692773'), (b'abc', 'da853b0d3f88d99b30283a69e6ded6bb'), (b'message digest', 'ab4f496bfb2a530b219ff33031fe06b0')]:
    rec('digest', '{ di_md2, %s, %s, "md2 rfc1319" }' % (blob(m), blob(bytes.fromhex(h))))

for name, di in dig.items():
    if name == 'md4': continue
    for kl in [0, 20, 64, 131]:
        for L in [0, 50, 200]:
            key, m = rb(kl), rb(L)
            rec('hmac', '{ %s, %s, %s, %s, "hmac-%s k%d m%d" }' % (di, blob(key), blob(m), blob(hmac.new(key, m, name).digest()), name, kl, L))
# rfc 4231 test case 2
rec('hmac', '{ di_sha256, %s, %s, %s, "hmac-sha256 rfc4231 tc2" }' % (blob(b'Jefe'), blob(b'what do ya want for nothing?'),
    blob(bytes.fromhex('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'))))

def aes(key, mode): return Cipher(algorithms.AES(key), mode)
for kl in [16, 24, 32]:
    for L in [16, 48, 160]:
        key, iv, pt = rb(kl), rb(16), rb(L)
        rec('blk', '{ "aes ecb", 0, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.ECB()).encryptor().update(pt))))
        rec('blk', '{ "aes cbc", 1, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.CBC(iv)).encryptor().update(pt))))
    for L in [1, 15, 16, 17, 100, 1000]:
        key, iv, pt = rb(kl), rb(16), rb(L)
        rec('blk', '{ "aes ctr", 2, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.CTR(iv)).encryptor().update(pt))))
        rec('blk', '{ "aes cfb", 3, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.CFB(iv)).encryptor().update(pt))))
        rec('blk', '{ "aes cfb8", 4, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.CFB8(iv)).encryptor().update(pt))))
        rec('blk', '{ "aes ofb", 5, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.OFB(iv)).encryptor().update(pt))))
# legacy ciphers through their mode objects
for cname, alg, kls in [('des3', TripleDES, [24]), ('blowfish', Blowfish, [16, 56]), ('cast', CAST5, [16])]:
    for kl in kls:
        key, iv, pt = rb(kl), rb(8), rb(64)
        idx = {'des3': 10, 'blowfish': 20, 'cast': 30}[cname]
        C = lambda m: Cipher(alg(key), m).encryptor().update(pt)
        rec('blk', '{ "%s ecb", %d, %s, %s, %s, %s }' % (cname, idx + 0, blob(key), blob(iv), blob(pt), blob(C(modes.ECB()))))
        rec('blk', '{ "%s cbc", %d, %s, %s, %s, %s }' % (cname, idx + 1, blob(key), blob(iv), blob(pt), blob(C(modes.CBC(iv)))))
        rec('blk', '{ "%s cfb", %d, %s, %s, %s, %s }' % (cname, idx + 3, blob(key), blob(iv), blob(pt), blob(C(modes.CFB(iv)))))
        rec('blk', '{ "%s ofb", %d, %s, %s, %s, %s }' % (cname, idx + 5, blob(key), blob(iv), blob(pt), blob(C(modes.OFB(iv)))))
# single des, fips 81 / sp 800-17 style known answer (key 0123456789abcdef, "Now is t")
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as T
kd = bytes.fromhex('0123456789abcdef')
ct = Cipher(T(kd * 3), modes.ECB()).encryptor().update(b'Now is t')
assert ct.hex() == '3fa40e8a984d4815'
rec('blk', '{ "des ecb", 40, %s, %s, %s, %s }' % (blob(kd), blob(bytes(8)), blob(b'Now is t'), blob(ct)))

# des cbc-mac via ccdes_cbc_cksum: last cbc block of the zero-padded input
for L in [8, 13, 32]:
    key, iv, m = rb(8), rb(8), rb(L)
    padded = m + bytes((-L) % 8)
    ct = Cipher(TripleDES(key * 3), modes.CBC(iv)).encryptor().update(padded)
    rec('cksum', '{ %s, %s, %s, %s }' % (blob(key), blob(iv), blob(m), blob(ct[-8:])))

# pkcs#7 over cbc (rfc 5652 6.3)
from cryptography.hazmat.primitives import padding as P
for L in [0, 1, 15, 16, 17, 31, 32, 100]:
    key, iv, pt = rb(16), rb(16), rb(L)
    pd = P.PKCS7(128).padder(); padded = pd.update(pt) + pd.finalize()
    rec('pkcs7', '{ %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(aes(key, modes.CBC(iv)).encryptor().update(padded))))
# big pkcs#7 runs: plaintext is generated in c, so only the ciphertext hash is stored
key16 = bytes(range(16)); iv16 = bytes(range(16, 32))
def big_pt(L): return bytes((i * 7 + (i >> 8)) & 0xff for i in range(L))
for L in [16, 4096, 1 << 20, 4 << 20]:
    pt = big_pt(L)
    pd = P.PKCS7(128).padder(); padded = pd.update(pt) + pd.finalize()
    ct = aes(key16, modes.CBC(iv16)).encryptor().update(padded)
    rec('pkcs7big', '{ %d, %s }' % (L, blob(hashlib.sha256(ct).digest())))

# cs3 reference built on ecb from the sp 800-38a addendum definition
def cs3_encrypt(key, iv, pt):
    e = aes(key, modes.ECB()).encryptor()
    bs = 16
    if len(pt) == bs: return aes(key, modes.CBC(iv)).encryptor().update(pt)
    d = len(pt) % bs or bs
    head = len(pt) - d - bs
    c = aes(key, modes.CBC(iv)).encryptor().update(pt[:head]) if head else b''
    prev = c[-16:] if head else iv
    cn1 = e.update(bytes(a ^ b for a, b in zip(pt[head:head + 16], prev)))
    last = pt[head + 16:] + bytes(16 - d)
    cn = e.update(bytes(a ^ b for a, b in zip(last, cn1)))
    return c + cn + cn1[:d]
for L in [16, 17, 31, 32, 33, 47, 48, 64, 100]:
    key, iv, pt = rb(16), rb(16), rb(L)
    rec('cts3', '{ %s, %s, %s, %s }' % (blob(key), blob(iv), blob(pt), blob(cs3_encrypt(key, iv, pt))))

# xts (sp 800-38e) with stealing for partial tails
for kl in [16, 32]:
    for L in [16, 17, 31, 32, 33, 64, 100, 512]:
        k1, k2 = rb(kl), rb(kl)
        tw, pt = rb(16), rb(L)
        ct = Cipher(algorithms.AES(k1 + k2), modes.XTS(tw)).encryptor().update(pt)
        rec('xts', '{ %s, %s, %s, %s, %s }' % (blob(k1), blob(k2), blob(tw), blob(pt), blob(ct)))

# gcm (sp 800-38d), test case 2 of the gcm spec checked first
assert AESGCM(bytes(16)).encrypt(bytes(12), bytes(16), None).hex() == '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf'
for kl in [16, 24, 32]:
    for ivl in [12, 8, 16, 60]:
        for L, A in [(0, 0), (16, 0), (60, 20), (1, 1), (100, 33)]:
            key, iv, aad, pt = rb(kl), rb(ivl), rb(A), rb(L)
            for tl in [16, 12]:
                if ivl != 12 and tl != 16: continue
                full = AESGCM(key).encrypt(iv, pt, aad if A else None)
                rec('gcm', '{ %s, %s, %s, %s, %s, %s }' % (blob(key), blob(iv), blob(aad), blob(pt), blob(full[:-16]), blob(full[-16:][:tl])))

# ccm (sp 800-38c), example c.1 checked first
c1 = AESCCM(bytes.fromhex('404142434445464748494a4b4c4d4e4f'), tag_length=4).encrypt(bytes.fromhex('10111213141516'), bytes.fromhex('20212223'), bytes.fromhex('0001020304050607'))
assert c1.hex() == '7162015b4dac255d'
for nl in [7, 8, 12, 13]:
    for tl in [4, 8, 16]:
        for L, A in [(0, 8), (4, 8), (16, 0), (24, 20), (100, 300)]:
            key, nonce, aad, pt = rb(16), rb(nl), rb(A), rb(L)
            full = AESCCM(key, tag_length=tl).encrypt(nonce, pt, aad if A else None)
            rec('ccm', '{ %s, %s, %s, %s, %s, %s }' % (blob(key), blob(nonce), blob(aad), blob(pt), blob(full[:-tl]), blob(full[-tl:])))

# chacha20-poly1305, rfc 8439 2.8.2 first
k = bytes(range(0x80, 0xa0)); nonce = bytes.fromhex('070000004041424344454647'); aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
full = ChaCha20Poly1305(k).encrypt(nonce, pt, aad)
assert full[-16:].hex() == '1ae10b594f09e26a7e902ecbd0600691'
rec('chapoly', '{ %s, %s, %s, %s, %s, %s }' % (blob(k), blob(nonce), blob(aad), blob(pt), blob(full[:-16]), blob(full[-16:])))
for L, A in [(0, 0), (1, 0), (64, 0), (65, 13), (300, 64)]:
    k, nonce, aad, pt = rb(32), rb(12), rb(A), rb(L)
    full = ChaCha20Poly1305(k).encrypt(nonce, pt, aad if A else None)
    rec('chapoly', '{ %s, %s, %s, %s, %s, %s }' % (blob(k), blob(nonce), blob(aad), blob(pt), blob(full[:-16]), blob(full[-16:])))

# pbkdf2 (rfc 6070 vectors 1 and 2, then oracle)
assert hashlib.pbkdf2_hmac('sha1', b'password', b'salt', 2, 20).hex() == 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'
for name, di in [('sha1', 'di_sha1'), ('sha256', 'di_sha256'), ('sha512', 'di_sha512')]:
    for it, dl in [(1, 20), (2, 20), (4096, 32), (3, 100)]:
        pw, salt = rb(rnd.randint(0, 40)), rb(rnd.randint(0, 24))
        rec('pbkdf2', '{ %s, %s, %s, %d, %s }' % (di, blob(pw), blob(salt), it, blob(hashlib.pbkdf2_hmac(name, pw, salt, it, dl))))
rec('pbkdf2', '{ di_sha1, %s, %s, 2, %s }' % (blob(b'password'), blob(b'salt'), blob(bytes.fromhex('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'))))

# hkdf (rfc 5869 a.1, then oracle)
ikm = bytes([0x0b] * 22); salt = bytes(range(13)); info = bytes(range(0xf0, 0xfa))
okm = HKDF(hashes.SHA256(), 42, salt, info).derive(ikm)
assert okm.hex().startswith('3cb25f25faacd57a90434f64d0362f2a')
rec('hkdf', '{ di_sha256, %s, %s, %s, %s }' % (blob(ikm), blob(salt), blob(info), blob(okm)))
for hn, di, h in [('sha1', 'di_sha1', hashes.SHA1()), ('sha512', 'di_sha512', hashes.SHA512())]:
    for sl, il, dl in [(0, 0, 20), (16, 10, 64), (80, 80, 82)]:
        ikm, salt, info = rb(30), rb(sl), rb(il)
        okm = HKDF(h, dl, salt if sl else None, info).derive(ikm)
        rec('hkdf', '{ %s, %s, %s, %s, %s }' % (di, blob(ikm), blob(salt), blob(info), blob(okm)))

# aes-cmac (rfc 4493 4 examples, then oracle)
k = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
cm = cmac.CMAC(algorithms.AES(k)); cm.update(b''); assert cm.finalize().hex() == 'bb1d6929e95937287fa37d129b756746'
for L in [0, 16, 40, 64, 1, 15, 17, 33, 100]:
    key, m = (k if L in (0, 16, 40, 64) else rb(16)), rb(L)
    cm = cmac.CMAC(algorithms.AES(key)); cm.update(m)
    rec('cmac', '{ %s, %s, %s }' % (blob(key), blob(m), blob(cm.finalize())))

# key wrap (rfc 3394 4.1, then oracle)
kek = bytes.fromhex('000102030405060708090a0b0c0d0e0f'); kd = bytes.fromhex('00112233445566778899aabbccddeeff')
w = keywrap.aes_key_wrap(kek, kd); assert w.hex() == '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'
rec('wrap', '{ %s, %s, %s }' % (blob(kek), blob(kd), blob(w)))
for kl, dl in [(16, 24), (24, 32), (32, 64)]:
    kek, kd = rb(kl), rb(dl)
    rec('wrap', '{ %s, %s, %s }' % (blob(kek), blob(kd), blob(keywrap.aes_key_wrap(kek, kd))))

# x9.63 kdf and sp 800-108 counter kdf
for dl in [16, 32, 70]:
    z, si = rb(32), rb(rnd.randint(0, 20))
    rec('x963', '{ di_sha256, %s, %s, %s }' % (blob(z), blob(si), blob(X963KDF(hashes.SHA256(), dl, si).derive(z))))
for dl in [16, 32, 70]:
    kdk, label, ctxt = rb(32), rb(8), rb(12)
    kb = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, dl, 4, 4, CounterLocation.BeforeFixed, label, ctxt, None)
    rec('nistkdf', '{ di_sha256, %s, %s, %s, %s }' % (blob(kdk), blob(label), blob(ctxt), blob(kb.derive(kdk))))

with open(sys.argv[1], 'w') as f:
    f.write('// generated by gen_vectors.py, do not edit\n#include <stdint.h>\n#include <stddef.h>\n')
    f.write('\n'.join(out) + '\n')
    for kind, rows in recs.items():
        f.write('static const struct pd_%s_vec pd_%s_vecs[] = {\n    %s\n};\n' % (kind, kind, ',\n    '.join(rows)))
print({k: len(v) for k, v in recs.items()})
