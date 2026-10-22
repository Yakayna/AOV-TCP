import sys,os,struct,json
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from pcapmini import read_pcap
import lq_decrypt
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C=b"";S=b""
def parse(buf):
    out=[];i=0
    while i+21<=len(buf):
        if buf[i]==0x33 and buf[i+1]==0x66:
            hl=struct.unpack_from("<H",buf,i+16)[0]; bl=struct.unpack_from(">H",buf,i+19)[0]
            if 21<=hl and i+hl+bl<=len(buf):
                out.append({"hl":hl,"bl":bl,"cmd":int.from_bytes(buf[i+6:i+8],"big"),"raw":buf[i:i+hl+bl]}); i+=hl+bl; continue
        i+=1
    return out
for x in read_pcap((sys.argv[1] if len(sys.argv)>1 else os.path.join(ROOT,"captures","fr2.pcap"))):
    if x["proto"]!="TCP" or not x.get("payload"): continue
    if x["dport"] in (6629,6630): C+=x["payload"]
    elif x["sport"] in (6629,6630): S+=x["payload"]
sf=parse(S); cf=parse(C)
key=None
for f in sf:
    if f["cmd"]==0x1002: key=f["raw"][23:39]
for f in cf:
    if f["cmd"]==0x4013:
        b=f["raw"][f["hl"]:]
        pt=lq_decrypt.aes128_cbc_decrypt(key,b[:16],b[16:])
        if len(pt)==112:
            open(os.path.join(ROOT,"captures","f0_payload.bin"),"wb").write(pt[:103]); print("saved f0 payload",len(pt[:103])); break
