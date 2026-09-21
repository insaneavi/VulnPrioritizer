import json, os
from pathlib import Path
from urllib.parse import quote
class NetworkConfig:
    def __init__(self,root=None):
        self.root=Path(root or os.environ.get("CONFIG_ROOT","/app/config")); self.root.mkdir(parents=True,exist_ok=True); self.path=self.root/"network.json"
    def load(self):
        d={"enabled":False,"protocol":"http","host":"","port":"","username":"","password":""}
        try: d.update(json.loads(self.path.read_text(encoding="utf-8")))
        except Exception: pass
        return d
    def save(self,d):
        c=self.load(); c.update(d); c["enabled"]=bool(d.get("enabled",False)); c["protocol"]=c["protocol"] if c["protocol"] in ("http","https") else "http"
        t=self.path.with_suffix(".tmp"); t.write_text(json.dumps(c,indent=2),encoding="utf-8"); os.chmod(t,0o600); os.replace(t,self.path); return c
    def public(self):
        c=self.load(); c["has_password"]=bool(c["password"]); c["password"]=""; return c
    def proxies(self):
        c=self.load()
        if not c["enabled"] or not c["host"] or not c["port"]: return None
        auth=""
        if c["username"]: auth=quote(c["username"],safe="")+(":"+quote(c["password"],safe="") if c["password"] else "")+"@"
        u=f'{c["protocol"]}://{auth}{c["host"]}:{c["port"]}'; return {"http":u,"https":u}
    def masked_proxy(self):
        c=self.load(); return f'{c["protocol"]}://{c["host"]}:{c["port"]}' if c["enabled"] else "Direct"
