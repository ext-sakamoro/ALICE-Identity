# Independent reference for the enrollment test vectors (tests/data/enrollment_vectors.json).
# hashlib + base64 + pynacl only; each layout is written byte by byte from the module documentation of
# src/enrollment.rs, not from the crate.
# Run: uv run --no-project --with pynacl python3 -I scripts/gen_enrollment_vectors.py > tests/data/enrollment_vectors.json
import hashlib, base64, json, nacl.signing
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def sk(seed): return nacl.signing.SigningKey(bytes([seed]*32))
def pub(k): return bytes(k.verify_key)
def sign(k, ctx, body): return bytes(k.sign(ctx + body).signature)
def u16(n): return n.to_bytes(2, "big")
def u64(n): return n.to_bytes(8, "big")
def b32(b): return base64.b32encode(b).decode().rstrip("=")

def ticket(master, subject, ticket_id, issued_at, not_after):
    s = subject.encode()
    body = bytes([1]) + u16(len(s)) + s + pub(master) + ticket_id + u64(issued_at) + u64(not_after)
    return body + sign(master, b"alice-identity enrollment-ticket v1", body)

def request(device, subject, master_pub, ticket_id, noise, requested_at):
    s = subject.encode()
    body = bytes([1]) + u16(len(s)) + s + master_pub + ticket_id + pub(device) + noise + u64(requested_at)
    return body + sign(device, b"alice-identity enrollment-request v1", body)

def short_code(req):
    h = hashlib.sha256(b"alice-identity enrollment-request short-code v1" + req).digest()[:7]
    n = int.from_bytes(h, "big") >> 6; out = ""
    for i in range(10): out = CROCKFORD[n & 31] + out; n >>= 5
    return out[:5] + "-" + out[5:]

def device_cert(master, subject, device_pub, noise, issued_at, not_after):
    s = subject.encode()
    did_id = hashlib.sha256(b"alice-identity/device-id/v1" + u16(len(s)) + s + device_pub).digest()[:16]
    body = bytes([3]) + u16(len(s)) + s + device_pub + noise + u64(issued_at) + u64(not_after) + did_id + pub(master)
    return body + sign(master, b"alice-identity device-cert v2", body)

m, d = sk(7), sk(9)
subject = "did:alice:enroll-oracle"
tid = bytes(range(16, 32))
noise = bytes([0x44] * 32)
t = ticket(m, subject, tid, 1_800_000_000, 1_800_000_600)
r = request(d, subject, pub(m), tid, noise, 1_800_000_060)
g = device_cert(m, subject, pub(d), noise, 1_800_000_120, 1_800_000_120 + 86_400 * 365)
print(json.dumps({
  "master_seed": 7, "device_seed": 9, "subject": subject, "ticket_id_hex": tid.hex(),
  "noise_hex": noise.hex(), "ticket_issued_at": 1_800_000_000, "ticket_not_after": 1_800_000_600,
  "requested_at": 1_800_000_060, "grant_issued_at": 1_800_000_120, "grant_not_after": 1_800_000_120 + 86_400 * 365,
  "ticket_hex": t.hex(), "ticket_text": "ALICE-ENROLL:1:" + b32(t),
  "request_hex": r.hex(), "request_text": "ALICE-ENROLL-REQ:1:" + b32(r),
  "short_code": short_code(r), "grant_hex": g.hex(),
}, indent=1))
