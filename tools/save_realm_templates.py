import sys,os,struct,json
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from pcapmini import read_pcap
import lq_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def parse(buf):
    out=[];i=0
    while i+21<=len(buf):
        if buf[i]==0x33 and buf[i+1]==0x66:
            hl=struct.unpack_from("<H",buf,i+16)[0]; bl=struct.unpack_from(">H",buf,i+19)[0]
            if 21<=hl and i+hl+bl<=len(buf):
                out.append({"hl":hl,"bl":bl,"cmd":int.from_bytes(buf[i+6:i+8],"big"),"seq":struct.unpack_from("<I",buf,i+12)[0],"raw":buf[i:i+hl+bl]}); i+=hl+bl; continue
        i+=1
    return out
C=b"";S=b""
for x in read_pcap((sys.argv[1] if len(sys.argv)>1 else os.path.join(ROOT,"captures","fr2.pcap"))):
    if x["proto"]!="TCP" or not x.get("payload"): continue
    if x.get("dport")==6670: C+=x["payload"]
    elif x.get("sport")==6670: S+=x["payload"]
cf=parse(C); sf=parse(S); key=None
for f in sf:
    if f["cmd"]==0x1002: key=f["raw"][23:39]
reports=[]; cstop=None
from cryptography.hazmat.primitives.ciphers import Cipher as C2,algorithms as A2,modes as M2
def ecbd(k,d):
    c=C2(A2.AES(k),M2.ECB()).decryptor(); return c.update(d)+c.finalize()
for f in cf:
    if f["cmd"]==0x4013:
        b=f["raw"][f["hl"]:]
        pt=lq_decrypt.aes128_cbc_decrypt(key,b[:16],b[16:])
        reports.append({"payload":pt.hex(),"iv":ecbd(key,b[:16]).hex(),"hdr":f["raw"][:f["hl"]].hex(),"seq":f["seq"]})
    if f["cmd"]==0x5001:
        b=f["raw"][f["hl"]:]
        try:
            pt=lq_decrypt.aes128_cbc_decrypt(key,b[:16],b[16:])
            cstop={"payload":pt.hex(),"iv":ecbd(key,b[:16]).hex(),"hdr":f["raw"][:f["hl"]].hex(),"seq":f["seq"]}
        except Exception: pass
json.dump({"reports":reports,"cstop":cstop},open(os.path.join(ROOT,"captures","realm_templates.json"),"w"),indent=1)
print("saved",len(reports),"reports, cstop",bool(cstop))
