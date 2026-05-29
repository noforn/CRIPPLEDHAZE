import sys

ck2 = b"9832gf2bc29_120e9hd10c))b@@!11"
ck2l = 30

def bin_to_c_enc(data, name):
    enc_data = bytearray()
    for i in range(len(data)):
        enc_data.append(data[i] ^ ck2[i % ck2l])
    
    res = f"unsigned char {name}[] = {{\n"
    chunks = [enc_data[i:i+16] for i in range(0, len(enc_data), 16)]
    for chunk in chunks:
        res += "    " + ", ".join([f"0x{x:02x}" for x in chunk]) + ",\n"
    res += "};\n"
    res += f"unsigned int {name}_len = {len(data)};\n"
    return res

sys_path = "/SADDLEBACK/ops/neusploit/DriversCloud/DriversCloud/STAGE/DriversCloud_amd64.sys"
dll_path = "/SADDLEBACK/ops/neusploit/DriversCloud/DriversCloud/STAGE/mmdevlib.dll"

with open(sys_path, "rb") as f:
    sys_data = f.read()

with open(dll_path, "rb") as f:
    dll_data = f.read()

with open("/SADDLEBACK/ops/neusploit/DriversCloud/DriversCloud/STAGE/payloads.h", "w") as f:
    f.write(bin_to_c_enc(sys_data, "file_sys"))
    f.write(bin_to_c_enc(dll_data, "file_dll"))

print("payloads.h generated with encrypted data.")
