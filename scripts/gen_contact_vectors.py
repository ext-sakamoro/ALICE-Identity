# Independent reference for the contact card, invite and safety number test vectors (tests/data/contact_vectors.json).
# hashlib + base64 + pynacl only; each layout is written byte by byte from the module documentation, not from the crate.
# Run: uv run --no-project --with pynacl python3 -I scripts/gen_contact_vectors.py > tests/data/contact_vectors.json
import hashlib, base64, json, sys, nacl.signing
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
def sk(seed): return nacl.signing.SigningKey(bytes([seed]*32))
def pub(k): return bytes(k.verify_key)
def did_key(p): return "did:key:z" + b58(b"\xed\x01" + p)
def sign(k, ctx, body): return bytes(k.sign(ctx + body).signature)
def u16(n): return n.to_bytes(2, "big")
def u32(n): return n.to_bytes(4, "big")
def u64(n): return n.to_bytes(8, "big")
def b32(b): return base64.b32encode(b).decode().rstrip("=")

def device_cert(master, subject, device_pub, noise, issued_at, not_after):
    s = subject.encode()
    did_id = hashlib.sha256(b"alice-identity/device-id/v1" + u16(len(s)) + s + device_pub).digest()[:16]
    body = bytes([3]) + u16(len(s)) + s + device_pub + noise + u64(issued_at) + u64(not_after) + did_id + pub(master)
    return body + sign(master, b"alice-identity device-cert v2", body)

def contact_card(master, certs, revocation, issued_at):
    s = did_key(pub(master)).encode()
    body = bytes([1]) + u16(len(s)) + s + pub(master) + u64(issued_at) + bytes([len(certs)])
    for c in certs: body += u16(len(c)) + c
    body += u32(len(revocation)) + revocation
    return body + sign(master, b"alice-identity contact-card v1", body)

def short_code(card):
    h = hashlib.sha256(b"alice-identity contact-card short-code v1" + card).digest()[:5]
    n = int.from_bytes(h, "big"); out = ""
    for i in range(8): out = CROCKFORD[n & 31] + out; n >>= 5
    return out[:4] + "-" + out[4:]

def invite(master, invite_id, issued_at, not_after):
    s = did_key(pub(master)).encode()
    body = bytes([1]) + u16(len(s)) + s + pub(master) + invite_id + u64(issued_at) + u64(not_after)
    return body + sign(master, b"alice-identity invite v1", body)

def party(p):
    d = did_key(p).encode()
    h = hashlib.sha256(b"alice-identity safety-number v1" + u16(len(d)) + d + p).digest()
    for _ in range(5200): h = hashlib.sha256(h + p).digest()
    return h, "".join(f"{int.from_bytes(h[5*i:5*i+5],'big') % 100000:05d}" for i in range(6))

def safety(a, b):
    (ha, da), (hb, db) = party(a), party(b)
    digits = "".join(sorted([da, db]))
    raw = b"".join(sorted([ha, hb]))
    return digits, raw

m = sk(7)
c1 = device_cert(m, did_key(pub(m)), bytes([9]*32), bytes([0x4e]*32), 1_800_000_000, 1_800_086_400)
c2 = device_cert(m, did_key(pub(m)), bytes([10]*32), bytes([0x4f]*32), 1_800_000_000, 1_800_086_400)
card = contact_card(m, [c1, c2], b"", 1_800_000_100)
inv = invite(m, bytes(range(16)), 1_800_000_000, 1_800_003_600)
a, b = pub(sk(1)), pub(sk(2))
sd, sr = safety(a, b)
out = {
  "contact_card": {"master_seed": 7, "subject": did_key(pub(m)), "issued_at": 1_800_000_100,
     "certs": [{"device_seed_byte": 9, "noise_byte": 0x4e}, {"device_seed_byte": 10, "noise_byte": 0x4f}],
     "cert_issued_at": 1_800_000_000, "cert_not_after": 1_800_086_400,
     "cert_bytes_hex": [c1.hex(), c2.hex()],
     "bytes_hex": card.hex(), "text": "ALICE-CARD:1:" + b32(card), "short_code": short_code(card)},
  "invite": {"master_seed": 7, "invite_id_hex": bytes(range(16)).hex(), "issued_at": 1_800_000_000,
     "not_after": 1_800_003_600, "bytes_hex": inv.hex(), "text": "ALICE-INVITE:1:" + b32(inv)},
  "safety_number": {"seed_a": 1, "seed_b": 2, "pub_a_hex": a.hex(), "pub_b_hex": b.hex(),
     "digits": sd, "bytes_hex": sr.hex()},
}
json.dump(out, sys.stdout, indent=2); print()
