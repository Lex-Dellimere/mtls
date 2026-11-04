# Builds the fixtures that openssl will not make: a v1 root, a certificate
# with the same extension twice, one with trailing bytes. Run by make.sh.
import base64, subprocess, sys

def tlv(tag, body):
    n = len(body)
    if n < 128:
        h = bytes([tag, n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        h = bytes([tag, 0x80 | len(b)]) + b
    return h + body

def parse(buf):
    out = []
    i = 0
    while i < len(buf):
        tag = buf[i]
        n = buf[i + 1]
        j = i + 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[j:j + k], "big")
            j += k
        out.append((tag, buf[j:j + n]))
        i = j + n
    return out

def pem_to_der(path):
    lines = [l for l in open(path).read().splitlines() if l and not l.startswith("-----")]
    return base64.b64decode("".join(lines))

def der_to_pem(der, path):
    b = base64.b64encode(der).decode()
    with open(path, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\n")
        for i in range(0, len(b), 64):
            f.write(b[i:i + 64] + "\n")
        f.write("-----END CERTIFICATE-----\n")

def sign_ed25519(key, data):
    open("craft.tbs", "wb").write(data)
    subprocess.check_call(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key,
                           "-in", "craft.tbs", "-out", "craft.sig"])
    sig = open("craft.sig", "rb").read()
    return sig

def assemble(tbs_fields, alg, key, path):
    tbs = tlv(0x30, b"".join(tbs_fields))
    sig = sign_ed25519(key, tbs)
    cert = tlv(0x30, tbs + alg + tlv(0x03, b"\x00" + sig))
    der_to_pem(cert, path)
    return cert

def fields_of(pem):
    cert = parse(pem_to_der(pem))[0][1]
    tbs, alg, sig = parse(cert)
    f = parse(tbs[1])
    return f, tlv(alg[0], alg[1])

def whole(item):
    return tlv(item[0], item[1])

# v1 root: the root certificate without version and extensions, same key.
f, alg = fields_of("root.pem")
# f = [version, serial, sigalg, issuer, validity, subject, spki, exts]
v1 = [whole(x) for x in f[1:7]]
assemble(v1, alg, "root.key", "root_v1.pem")

# A leaf whose extension list repeats the basicConstraints extension.
f, alg = fields_of("leaf.pem")
exts = parse(parse(f[-1][1])[0][1])
bc = [e for e in exts if parse(e[1])[0][1] == bytes.fromhex("551d13")][0]
dup = [whole(e) for e in exts] + [whole(bc)]
newext = tlv(0xA3, tlv(0x30, b"".join(dup)))
assemble([whole(x) for x in f[:-1]] + [newext], alg, "inter.key", "leaf_dupext.pem")

# A leaf with an explicit DEFAULT value (version 1 spelled out as [0] 0).
ver0 = tlv(0xA0, tlv(0x02, b"\x00"))
assemble([ver0] + [whole(x) for x in f[1:]], alg, "inter.key", "leaf_ver0.pem")

# A leaf whose basicConstraints says cA FALSE explicitly (DER leaves it out).
bcfalse = tlv(0x30, tlv(0x06, bytes.fromhex("551d13")) + tlv(0x01, b"\xff") +
              tlv(0x04, tlv(0x30, tlv(0x01, b"\x00"))))
exts2 = [whole(e) if e is not bc else bcfalse for e in exts]
newext2 = tlv(0xA3, tlv(0x30, b"".join(exts2)))
assemble([whole(x) for x in f[:-1]] + [newext2], alg, "inter.key", "leaf_bcfalse.pem")

# Trailing byte after the certificate.
der = pem_to_der("leaf.pem") + b"\x00"
der_to_pem(der, "leaf_trailing.pem")

for p in ("craft.tbs", "craft.sig"):
    import os
    os.remove(p)
