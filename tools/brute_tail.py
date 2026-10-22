# -*- coding: utf-8 -*-
"""Brute 16-bit IV-struct tail for current MSDK token at gateway (clientless)."""
import json,os,socket,struct,sys,time,random,threading
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import lq_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FS=json.load(open(os.path.join(ROOT,"captures","connect_6670_frameset.json"),encoding="utf-8"))
tokj=json.load(open(os.path.join(ROOT,"captures","msdk_token.json"),encoding="utf-8"))["response"]
TOKEN=tokj["token"]; OPENID=str(tokj["openid"]); core=TOKEN[2:]
raw=bytearray(bytes.fromhex(FS["raw1001"].replace(" ","")))
i=bytes(raw).find(b"OPENID_PLACEHOLD")
if i>=0: raw[i:i+16]=OPENID.encode()
HEAD=bytes.fromhex("fffe02073534353008360b0b2547")
GATEWAYS=[("148.222.90.36",6629),("148.222.90.43",6630),("148.222.90.181",6629),("148.222.90.120",6630),
          ("148.222.90.69",6630),("148.222.90.213",6629),("148.222.90.58",6630),("148.222.90.165",6630),
          ("148.222.90.197",6629),("148.222.90.87",6630)]
def ecb(k,d):
    c=Cipher(algorithms.AES(k),modes.ECB()).encryptor(); return c.update(d)+c.finalize()
def enc(k,iv,d): return lq_decrypt.aes128_cbc_encrypt(k,iv,d)
def parse(buf):
    out=[];i=0
    while i+21<=len(buf):
        if buf[i]==0x33 and buf[i+1]==0x66:
            hl=struct.unpack_from("<H",buf,i+16)[0]; bl=struct.unpack_from(">H",buf,i+19)[0]
            if 21<=hl and i+hl+bl<=len(buf):
                out.append(int.from_bytes(buf[i+6:i+8],"big")); i+=hl+bl; continue
        i+=1
    return out
found=[]; stop=threading.Event(); lock=threading.Lock()
counter=[0]; total=65536; t0=time.time()
def attempt(tail, gw):
    try:
        s=socket.create_connection(gw,timeout=2.5); s.settimeout(0.5)
    except Exception:
        return
    try:
        key=None
        s.sendall(bytes(raw))
        end=time.time()+1.2
        buf=b""
        while time.time()<end and not key:
            try: ch=s.recv(65536)
            except socket.timeout: break
            except Exception: break
            if not ch: break
            buf+=ch; j=buf.find(b"\x33\x66")
            if j>=0 and len(buf)>=j+39: key=buf[j+23:j+39]
        if not key: return
        iv=ecb(key,HEAD+struct.pack(">H",tail))
        pt=core.encode()+b"\x00"*(64-len(core)-7)+bytes([random.randrange(256)])+b"tsf4g"+b"\x07"
        body=iv+enc(key,iv,pt)
        h=bytearray(bytes.fromhex(FS["raw2001_header"].replace(" ",""))); struct.pack_into(">H",h,19,len(body))
        s.sendall(bytes(h)+body); s.settimeout(0.8)
        buf=b""
        end=time.time()+0.9
        while time.time()<end:
            try: ch=s.recv(65536)
            except socket.timeout: break
            except Exception: break
            if not ch: break
            buf+=ch
            cmds=parse(buf)
            if 0x2002 in cmds:
                with lock:
                    found.append((tail,key.decode("latin1")))
                    json.dump({"openid":OPENID,"token":TOKEN,"tail":"%04x"%tail,"key":key.decode("latin1"),"when":time.strftime("%Y-%m-%d %H:%M:%S")},
                              open(os.path.join(ROOT,"captures","tail_found.json"),"w"),indent=1)
                    try:
                        tf=os.path.join(ROOT,"captures","token_tails.json")
                        try: tails=json.load(open(tf,encoding="utf-8"))
                        except Exception: tails={}
                        tails[TOKEN]="%04x"%tail
                        json.dump(tails,open(tf,"w",encoding="utf-8"),indent=1)
                    except Exception: pass
                    print("[+] FOUND tail=%04x key=%s elapsed=%.1fs attempts=%d"%(tail,key.decode("latin1"),time.time()-t0,counter[0]),flush=True)
                    stop.set()
                return
            if 0x5002 in cmds: break
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass
def worker(wid):
    gw=GATEWAYS[wid%len(GATEWAYS)]
    while not stop.is_set():
        with lock:
            n=counter[0]
            if n>=total: return
            counter[0]+=1
        attempt(n, gw)
        if wid==0 and counter[0]%1000==0:
            print("[*] progress %d/%d elapsed=%.0fs"%(counter[0],total,time.time()-t0),flush=True)
print("[*] token",TOKEN[:16],"openid",OPENID,"threads 24",flush=True)
ths=[threading.Thread(target=worker,args=(i,),daemon=True) for i in range(24)]
for t in ths: t.start()
for t in ths: t.join()
if not found: print("[-] not found",flush=True)
