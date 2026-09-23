import csv
import gzip
import io
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from services.network_config import NetworkConfig

INTEL_ROOT = os.environ.get("INTEL_ROOT", "/app/intel")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def _http_get(*args, **kwargs):
    kwargs["proxies"] = NetworkConfig().proxies()
    return requests.get(*args, **kwargs)

class ThreatIntelManager:
    def __init__(self):
        self.root = INTEL_ROOT
        self.epss_dir = os.path.join(self.root, "epss")
        self.cisa_dir = os.path.join(self.root, "cisa")
        self.meta_dir = os.path.join(self.root, "metadata")
        for path in (self.epss_dir, self.cisa_dir, self.meta_dir):
            os.makedirs(path, exist_ok=True)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _meta_path(self, source):
        return os.path.join(self.meta_dir, f"{source}.json")

    def _load_meta(self, source):
        try:
            with open(self._meta_path(source), "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_meta(self, source, data):
        tmp = self._meta_path(source) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._meta_path(source))

    def _network_diagnostics(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        proxy_cfg = NetworkConfig()
        proxies = proxy_cfg.proxies()
        result = {
            "timestamp": self._now(), "url": url, "host": host, "port": port,
            "connection_method": proxy_cfg.masked_proxy(),
            "proxy_enabled": bool(proxies),
            "dns": "PROXY HANDLES DESTINATION" if proxies else "NOT ATTEMPTED",
            "resolved_ips": [], "tcp": "NOT ATTEMPTED", "tls": "NOT ATTEMPTED",
            "http_status": None, "final_url": None, "redirects": 0,
            "download_bytes": 0, "duration_seconds": None, "error": None
        }
        start = time.monotonic()

        # With an HTTP/HTTPS proxy, do not require the container to resolve or
        # connect directly to the destination. The proxy handles the CONNECT
        # tunnel and destination DNS. This mirrors the proven requests behavior.
        if proxies:
            c = proxy_cfg.load()
            try:
                with socket.create_connection((c["host"], int(c["port"])), timeout=10):
                    result["tcp"] = "PROXY SUCCESS"
                result["tls"] = "VIA PROXY REQUEST"
            except Exception as exc:
                result["tcp"] = "PROXY FAILED"
                result["error"] = f"PROXY TCP: {type(exc).__name__}: {exc}"
            result["duration_seconds"] = round(time.monotonic()-start, 3)
            return result

        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            result["resolved_ips"] = sorted({x[4][0] for x in infos})
            result["dns"] = "SUCCESS"
        except Exception as exc:
            result["dns"] = "FAILED"
            result["error"] = f"DNS: {type(exc).__name__}: {exc}"
            result["duration_seconds"] = round(time.monotonic()-start, 3)
            return result
        try:
            with socket.create_connection((host, port), timeout=10):
                result["tcp"] = "SUCCESS"
        except Exception as exc:
            result["tcp"] = "FAILED"
            result["error"] = f"TCP: {type(exc).__name__}: {exc}"
            result["duration_seconds"] = round(time.monotonic()-start, 3)
            return result
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    result["tls"] = "SUCCESS"
        except Exception as exc:
            result["tls"] = "FAILED"
            result["error"] = f"TLS: {type(exc).__name__}: {exc}"
        result["duration_seconds"] = round(time.monotonic()-start, 3)
        return result

    def _download(self, url):
        diag = self._network_diagnostics(url)
        if diag.get("error"):
            return None, diag
        if not diag.get("proxy_enabled") and (diag["dns"] != "SUCCESS" or diag["tcp"] != "SUCCESS" or diag["tls"] != "SUCCESS"):
            return None, diag
        start = time.monotonic()
        try:
            r = _http_get(url, timeout=(10, 90), allow_redirects=True,
                          headers={"User-Agent": "VulnPrioritizer/0.6.4"})
            diag["http_status"] = r.status_code
            diag["final_url"] = r.url
            diag["redirects"] = len(r.history)
            diag["download_bytes"] = len(r.content)
            diag["duration_seconds"] = round(time.monotonic()-start, 3)
            if diag.get("proxy_enabled"):
                diag["tls"] = "SUCCESS VIA PROXY" if r.status_code else diag["tls"]
            r.raise_for_status()
            return r.content, diag
        except Exception as exc:
            diag["error"] = f"HTTP: {type(exc).__name__}: {exc}"
            diag["duration_seconds"] = round(time.monotonic()-start, 3)
            return None, diag

    def update_epss(self):
        source = "epss"
        meta = self._load_meta(source)
        meta["last_attempted_update"] = self._now()
        meta["source_url"] = EPSS_URL
        content, diag = self._download(EPSS_URL)
        meta["last_diagnostics"] = diag
        if content is None:
            meta["last_update_status"] = "FAILED"
            meta["last_error"] = diag.get("error")
            self._save_meta(source, meta)
            return False

        try:
            text = gzip.decompress(content).decode("utf-8-sig")
            lines = text.splitlines()
            dataset_date = ""
            while lines and lines[0].startswith("#"):
                if "model_version" in lines[0] or "score_date" in lines[0]:
                    dataset_date = lines[0].lstrip("#").strip()
                lines.pop(0)
            reader = csv.DictReader(lines)
            if not reader.fieldnames or not {"cve","epss","percentile"}.issubset(set(reader.fieldnames)):
                raise ValueError("EPSS dataset missing required columns.")
            records = list(reader)
            if len(records) < 1000:
                raise ValueError(f"EPSS dataset record count unexpectedly low: {len(records)}")
            target = os.path.join(self.epss_dir, "epss_scores-current.csv.gz")
            tmp = target + ".tmp"
            with open(tmp, "wb") as f:
                f.write(content)
            os.replace(tmp, target)
            meta.update({
                "last_update_status":"SUCCESS", "last_error":None,
                "last_successful_update":self._now(), "dataset_date":dataset_date,
                "record_count":len(records), "download_bytes":len(content)
            })
            self._save_meta(source, meta)
            return True
        except Exception as exc:
            meta["last_update_status"] = "FAILED"
            meta["last_error"] = f"VALIDATION: {type(exc).__name__}: {exc}"
            self._save_meta(source, meta)
            return False

    def update_kev(self):
        source = "kev"
        meta = self._load_meta(source)
        meta["last_attempted_update"] = self._now()
        meta["source_url"] = KEV_URL
        content, diag = self._download(KEV_URL)
        meta["last_diagnostics"] = diag
        if content is None:
            meta["last_update_status"] = "FAILED"
            meta["last_error"] = diag.get("error")
            self._save_meta(source, meta)
            return False
        try:
            data = json.loads(content.decode("utf-8-sig"))
            vulns = data.get("vulnerabilities", [])
            if len(vulns) < 100:
                raise ValueError(f"KEV record count unexpectedly low: {len(vulns)}")
            if not all("cveID" in x for x in vulns[:20]):
                raise ValueError("KEV dataset missing expected cveID field.")
            target = os.path.join(self.cisa_dir, "known_exploited_vulnerabilities.json")
            tmp = target + ".tmp"
            with open(tmp, "wb") as f:
                f.write(content)
            os.replace(tmp, target)
            meta.update({
                "last_update_status":"SUCCESS", "last_error":None,
                "last_successful_update":self._now(),
                "dataset_date":data.get("dateReleased") or data.get("catalogVersion",""),
                "catalog_version":data.get("catalogVersion",""),
                "record_count":len(vulns), "download_bytes":len(content)
            })
            self._save_meta(source, meta)
            return True
        except Exception as exc:
            meta["last_update_status"] = "FAILED"
            meta["last_error"] = f"VALIDATION: {type(exc).__name__}: {exc}"
            self._save_meta(source, meta)
            return False

    def update_all(self):
        e = self.update_epss()
        k = self.update_kev()
        return {"success": e and k, "epss": e, "kev": k}

    def load_epss(self):
        path = os.path.join(self.epss_dir, "epss_scores-current.csv.gz")
        result = {}
        if not os.path.exists(path):
            return result
        try:
            with gzip.open(path, "rt", encoding="utf-8-sig") as f:
                lines = [line for line in f if not line.startswith("#")]
            for row in csv.DictReader(lines):
                result[row["cve"].upper()] = {
                    "epss": float(row["epss"]), "percentile": float(row["percentile"])
                }
        except Exception:
            return {}
        return result

    def load_kev(self):
        path = os.path.join(self.cisa_dir, "known_exploited_vulnerabilities.json")
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {x["cveID"].upper(): x for x in data.get("vulnerabilities", [])}
        except Exception:
            return {}

    def get_status(self):
        return {"epss": self._load_meta("epss"), "kev": self._load_meta("kev"),
                "epss_available": bool(self.load_epss()), "kev_available": bool(self.load_kev())}

    def get_diagnostics(self):
        return {"epss": self._load_meta("epss").get("last_diagnostics", {}),
                "kev": self._load_meta("kev").get("last_diagnostics", {})}
