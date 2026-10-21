#!/usr/bin/env python3
"""Scope-first reconnaissance for authorized security assessments. Python 3.10+."""
import argparse, hashlib, json, re, socket, ssl, sys, time, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0.0"
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def normalize_domain(value):
    name = value.strip().rstrip(".").lower()
    if not name or "://" in name or "/" in name or ":" in name: raise ValueError("provide a DNS domain, not a URL, IP, or host:port")
    try: name = name.encode("idna").decode("ascii")
    except UnicodeError as exc: raise ValueError("invalid IDNA domain") from exc
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253 or any(not x or len(x)>63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x) for x in labels): raise ValueError("invalid fully-qualified DNS domain")
    try:
        socket.inet_pton(socket.AF_INET, name); raise ValueError("IP literals are not accepted")
    except OSError: pass
    try:
        socket.inet_pton(socket.AF_INET6, name); raise ValueError("IP literals are not accepted")
    except OSError: pass
    return name

def in_scope(host, root):
    host = host.rstrip(".").lower()
    return host == root or host.endswith("." + root)

def discover(domain, timeout):
    names, errors = {domain}, []
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q":"%."+domain,"output":"json"})
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"ReconPipeline/"+VERSION})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(5_000_000).decode("utf-8"))
        if not isinstance(data, list): raise ValueError("unexpected CT response")
        for record in data:
            if isinstance(record, dict):
                for raw in str(record.get("name_value","")).splitlines():
                    raw = raw.strip().lower().removeprefix("*.")
                    try: name = normalize_domain(raw)
                    except ValueError: continue
                    if in_scope(name, domain): names.add(name)
    except (OSError, TimeoutError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        errors.append("CT lookup failed: "+type(exc).__name__+": "+str(exc))
    return names, errors

def resolve(host):
    start, ips, errors = time.monotonic(), set(), []
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM): ips.add(item[4][0])
    except socket.gaierror as exc: errors.append(str(exc))
    return {"host":host,"addresses":sorted(ips),"dns_resolved":bool(ips),"dns_errors":errors,"http":[],"elapsed_ms":round((time.monotonic()-start)*1000,2)}

def probe(host, timeout):
    results=[]; opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for scheme in ("https","http"):
        url=scheme+"://"+host+"/"; start=time.monotonic()
        req=urllib.request.Request(url,headers={"User-Agent":"ReconPipeline/"+VERSION,"Range":"bytes=0-0"})
        try:
            with opener.open(req,timeout=timeout) as res: code,headers,err=res.status,res.headers,None
        except urllib.error.HTTPError as exc: code,headers,err=exc.code,exc.headers,None
        except (OSError,TimeoutError,ssl.SSLError,urllib.error.URLError) as exc: code,headers,err=None,None,type(exc).__name__+": "+str(exc)
        results.append({"url":url,"status":code,"server":headers.get("Server") if headers else None,
          "content_type":headers.get("Content-Type") if headers else None,
          "redirect":headers.get("Location") if headers and code in (301,302,303,307,308) else None,
          "error":err,"elapsed_ms":round((time.monotonic()-start)*1000,2)})
    return results

def scan_ports(host, ports, timeout):
    out=[]
    for port in ports:
        start=time.monotonic()
        try:
            with socket.create_connection((host,port),timeout=timeout): state,err="open",None
        except (OSError,TimeoutError) as exc: state,err="not_confirmed_open",type(exc).__name__
        out.append({"host":host,"port":port,"state":state,"error":err,"elapsed_ms":round((time.monotonic()-start)*1000,2)})
    return out

def markdown(r):
    s=r["summary"]; lines=["# Reconnaissance Report: "+r["scope"]["root_domain"],"",
      "- Engagement: "+str(r["scope"].get("engagement_id") or "operator-acknowledged scope"),
      "- Scope expires UTC: "+str(r["scope"].get("expires_at") or "not specified"),
      "- Started UTC: "+r["started_at"],"- Completed UTC: "+r["completed_at"],
      "- Duration seconds: "+str(r["duration_seconds"]),"- Tool version: "+VERSION,
      "- Authorization acknowledgement recorded; permission is not independently verified.","",
      "## Summary",""]+[f"- {k.replace('_',' ').title()}: {v}" for k,v in s.items()]
    lines += ["","## Hosts","","| Host | Addresses | HTTP status |","|---|---|---|"]
    for h in r["hosts"]:
        statuses=", ".join(p["url"]+" -> "+str(p["status"] or "no response") for p in h["http"])
        lines.append("| "+h["host"]+" | "+(", ".join(h["addresses"]) or "—")+" | "+(statuses or "not checked")+" |")
    lines += ["","## TCP ports","","| Host | Port | State |","|---|---:|---|"]
    lines += ["| {host} | {port} | {state} |".format(**p) for p in r["tcp_observations"]] or ["| — | — | TCP checks not requested |"]
    lines += ["","## Errors and limitations",""]+["- "+e for e in r["errors"]]
    lines += ["","These are reconnaissance observations, not verified vulnerability claims. Passive data may be incomplete or stale.",""]
    return "\n".join(lines)

def run(a):
    if not a.authorized: raise ValueError("explicit authorization acknowledgement required; use --authorized only when permitted")
    domain=normalize_domain(a.target)
    scope_details={"root_domain":domain,"engagement_id":None,"expires_at":None,
      "allowed_hosts":[],"excluded_hosts":[],"scope_file_sha256":None,
      "policy":"root and dot-delimited subdomains only","authorization_acknowledged":True}
    scope_file=getattr(a,"scope_file",None)
    if scope_file:
        import recon_scope
        scope_details=recon_scope.load_scope(Path(scope_file),domain)
        scope_details["policy"]="time-bounded engagement manifest; allowed/excluded host rules applied"
        scope_details["authorization_acknowledged"]=True
    if not 1<=a.workers<=10: raise ValueError("workers must be 1-10")
    if not 1<=a.max_hosts<=1000: raise ValueError("max-hosts must be 1-1000")
    if not .5<=a.timeout<=30: raise ValueError("timeout must be 0.5-30 seconds")
    try: ports=sorted(set(int(x.strip()) for x in a.ports.split(","))) if a.ports else []
    except ValueError as exc: raise ValueError("ports must be comma-separated integers") from exc
    if len(ports)>32 or any(p<1 or p>65535 for p in ports): raise ValueError("choose up to 32 TCP ports in range 1-65535")
    started = datetime.now(timezone.utc)
    names,errors=discover(domain,a.timeout)
    if scope_file:
        names={n for n in names if recon_scope.host_is_in_scope(n,scope_details)}
    else:
        names={n for n in names if in_scope(n,domain)}
    if len(names)>a.max_hosts: names=set(sorted(names)[:a.max_hosts]); errors.append("Host cap reached")
    hosts=[]
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures=[pool.submit(resolve,n) for n in sorted(names)]
        for f in as_completed(futures):
            h=f.result()
            if h["dns_resolved"] and not a.no_http: h["http"]=probe(h["host"],a.timeout)
            hosts.append(h)
    hosts.sort(key=lambda x:x["host"])
    for h in hosts:
        errors.extend(h["host"]+": "+e for e in h["dns_errors"])
        errors.extend(p["url"]+": "+p["error"] for p in h["http"] if p["error"])
    tcp=[]
    if ports:
        with ThreadPoolExecutor(max_workers=min(a.workers,5)) as pool:
            futures=[pool.submit(scan_ports,h["host"],ports,a.timeout) for h in hosts if h["addresses"]]
            for f in as_completed(futures): tcp.extend(f.result())
        tcp.sort(key=lambda x:(x["host"],x["port"]))
    completed = datetime.now(timezone.utc)
    return {"schema_version":"1.0","tool":"Recon Pipeline","tool_version":VERSION,
      "run_id":started.strftime("%Y%m%dT%H%M%S%fZ"),"started_at":started.isoformat(),
      "completed_at":completed.isoformat(),"duration_seconds":round((completed-started).total_seconds(),3),
      "scope":scope_details,
      "methods":["passive Certificate Transparency","DNS resolution"]+([] if a.no_http else ["HTTP(S) probe"])+(["explicit TCP ports"] if ports else []),
      "summary":{"names_discovered":len(names),"dns_resolved_hosts":sum(bool(h["addresses"]) for h in hosts),
        "hosts_with_http_response":sum(any(p["status"] is not None for p in h["http"]) for h in hosts),
        "tcp_ports_open":sum(p["state"]=="open" for p in tcp),"errors":len(errors)},
      "hosts":hosts,"tcp_observations":tcp,"errors":errors,
      "limitations":["Authorization is operator-acknowledged, not independently verified.","CT data may be incomplete; no brute force is performed.","HTTP status and open ports do not confirm vulnerabilities.","No exploit testing is performed."]}

def main(argv=None):
    p=argparse.ArgumentParser(description="Scope-first reconnaissance for authorized assessments.")
    p.add_argument("target"); p.add_argument("--authorized",action="store_true")
    p.add_argument("--output-dir",default="recon_output"); p.add_argument("--workers",type=int,default=5)
    p.add_argument("--scope-file",type=Path,help="time-bounded JSON engagement scope manifest")
    p.add_argument("--max-hosts",type=int,default=100); p.add_argument("--timeout",type=float,default=4)
    p.add_argument("--ports",help="optional comma-separated TCP ports"); p.add_argument("--no-http",action="store_true")
    p.add_argument("--version",action="version",version="%(prog)s "+VERSION); a=p.parse_args(argv)
    try:
        r=run(a); out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
        (out/"report.json").write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        (out/"report.md").write_text(markdown(r),encoding="utf-8")
        (out/"run.log").write_text("\n".join(r["errors"])+"\n" if r["errors"] else "",encoding="utf-8")
        artifacts = []
        for filename, media_type in (("report.json", "application/json"),
                                     ("report.md", "text/markdown"),
                                     ("run.log", "text/plain")):
            raw = (out/filename).read_bytes()
            artifacts.append({"path": filename, "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "media_type": media_type})
        manifest = {"manifest_schema_version": "1.0", "tool": "Recon Pipeline",
                    "tool_version": VERSION, "run_id": r["run_id"],
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "root_domain": r["scope"]["root_domain"], "artifacts": artifacts,
                    "integrity_note": "SHA-256 detects changes against this manifest; it is not a digital signature or proof of source authenticity."}
        (out/"manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        print("Reports and integrity manifest written to "+str(out)); print(json.dumps(r["summary"],indent=2)); return 0
    except (ValueError,OSError) as exc: print("error: "+str(exc),file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
