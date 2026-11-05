"""Independent Python encoder for PSTCO-Pay offline records.

Writes golden.json. offline/golden_test.go rebuilds every vector in Go and
fails if a single byte differs, which proves Python and Go agree on the
wire format (amount encoding, field order, endianness, hashing).

    python sdk/offline/testdata/golden.py
"""
import hashlib
import json
from pathlib import Path


def amount_bytes(paise: int) -> bytes:
    if not 0 < paise < 1 << 40:
        raise ValueError(paise)
    return paise.to_bytes(5, "big")


def parse_inr(s: str) -> int:
    whole, dot, frac = s.partition(".")
    if not whole.isdigit() or (dot and not (1 <= len(frac) <= 2 and frac.isdigit())):
        raise ValueError(s)
    if len(whole) > 1 and whole[0] == "0":
        raise ValueError(s)
    paise = int(whole) * 100 + int((frac + "00")[:2])
    if not 0 < paise < 1 << 40:
        raise ValueError(s)
    return paise


def signed_bytes(v: dict) -> bytes:
    return (
        bytes([1])
        + v["device_id"].to_bytes(8, "big")
        + v["counter"].to_bytes(4, "big")
        + amount_bytes(v["amount_paise"])
        + v["payee_id"].to_bytes(8, "big")
        + v["timestamp"].to_bytes(4, "big")
        + v["expiry"].to_bytes(4, "big")
        + bytes.fromhex(v["prev_hash"])
    )


def payee_id(phone: str) -> int:
    d = hashlib.sha256(("PSTCO-PAYEE-1\n" + phone).encode()).digest()
    return int.from_bytes(d[:8], "big") or 1


VECTORS = [
    dict(device_id=0x0102030405060708, counter=1, amount_paise=parse_inr("123.45"),
         payee_id=payee_id("+919876543210"), timestamp=1793000000, expiry=1795592000,
         prev_hash="00112233445566778899aabbccddeeff"),
    dict(device_id=0x7FFFFFFFFFFFFFFF, counter=4294967295, amount_paise=(1 << 40) - 1,
         payee_id=0xFFFFFFFFFFFFFFFF, timestamp=0, expiry=4294967295,
         prev_hash="ffffffffffffffffffffffffffffffff"),
]

AMOUNTS = ["1", "0.01", "0.5", "123.45", "500", "10995116277.75"]

out = {
    "amounts": [{"input": a, "paise": parse_inr(a), "hex": amount_bytes(parse_inr(a)).hex()} for a in AMOUNTS],
    "payee_ids": [{"phone": p, "id": f"{payee_id(p):016x}"} for p in ["+919876543210", "+14155550100"]],
    "records": [],
}
for v in VECTORS:
    sb = signed_bytes(v)
    out["records"].append({
        **v,
        "signed_hex": sb.hex(),
        # The chain hash covers all 114 bytes; with a zero signature it is
        # deterministic without needing an Ed25519 library in Python.
        "hash_zero_sig": hashlib.sha256(sb + bytes(64)).digest()[:16].hex(),
    })

Path(__file__).with_name("golden.json").write_text(json.dumps(out, indent=2))
print(f"wrote {len(out['records'])} records, {len(out['amounts'])} amounts")
