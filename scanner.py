#!/usr/bin/env python3
"""Educational, non-exploitative scanner. Use only on systems you own or are authorized to test."""
import argparse, datetime, html, json, socket, urllib.request, urllib.parse

PORTS = {21:"FTP",22:"SSH",23:"Telnet",80:"HTTP",443:"HTTPS",3306:"MySQL",5432:"PostgreSQL",8080:"HTTP-alt",8443:"HTTPS-alt"}
HEADERS = {
 "strict-transport-security":("Missing HSTS","For HTTPS, configure Strict-Transport-Security."),
 "content-security-policy":("Missing Content-Security-Policy","Add a suitable Content-Security-Policy."),
 "x-content-type-options":("Missing X-Content-Type-Options","Set X-Content-Type-Options: nosniff."),
 "x-frame-options":("Missing X-Frame-Options","Set X-Frame-Options or CSP frame-ancestors."),
 "referrer-policy":("Missing Referrer-Policy","Set a privacy-conscious Referrer-Policy.")
}
def main():
 p=argparse.ArgumentParser(description="Limited port and HTTP-header scanner for authorized targets.")
 p.add_argument("target",help="Your own hostname or IP")
 p.add_argument("--authorized",action="store_true",help="Confirm you have permission")
 p.add_argument("--url",help="Optional HTTP(S) URL, e.g. http://127.0.0.1:8000")
 p.add_argument("--ports",default="21,22,23,80,443,3306,5432,8080,8443")
 p.add_argument("--timeout",type=float,default=1.2)
 p.add_argument("--out",default="scan_report")
 a=p.parse_args()
 if not a.authorized: p.error("Permission confirmation required. Use --authorized only for systems you own or have permission to test.")
 try:
  ports=sorted(set(int(x) for x in a.ports.split(",")))
  if not ports or len(ports)>20 or any(x<1 or x>65535 for x in ports): raise ValueError()
 except ValueError: p.error("Provide 1–20 valid TCP ports.")
 if not 0<a.timeout<=5: p.error("Timeout must be >0 and <=5 seconds.")
 try: ip=socket.gethostbyname(a.target)
 except socket.gaierror: p.error("Could not resolve target.")
 findings=[]; results=[]
 print(f"Scanning {a.target} ({ip})")
 for port in ports:
  s=socket.socket(); s.settimeout(a.timeout)
  try:
   opened=s.connect_ex((ip,port))==0
   results.append({"port":port,"service":PORTS.get(port,"Unknown"),"state":"open" if opened else "closed or filtered"})
   if opened:
    severity="Medium" if port in (21,23,3306,5432) else "Info"
    advice=("Disable Telnet/FTP if unnecessary; prefer encrypted alternatives." if port in (21,23) else
            "Restrict database access to trusted hosts." if port in (3306,5432) else
            "Confirm this service is required and access-controlled.")
    findings.append({"severity":severity,"title":f"Open port {port} ({PORTS.get(port,'Unknown')})",
                     "evidence":f"TCP connection accepted by {ip}:{port}.",
                     "recommendation":advice})
  except OSError as e: results.append({"port":port,"service":PORTS.get(port,"Unknown"),"state":"error: "+str(e)})
  finally: s.close()
 http_info=None
 if a.url:
  req=urllib.request.Request(a.url,headers={"User-Agent":"MiniVulnerabilityScanner/1.0"})
  try:
   with urllib.request.urlopen(req,timeout=a.timeout) as r:
    hs={k.lower():v for k,v in r.headers.items()}
    http_info={"url":a.url,"status":r.status,"headers":dict(r.headers)}
    for key,(title,fix) in HEADERS.items():
     if key=="strict-transport-security" and urllib.parse.urlparse(a.url).scheme!="https": continue
     if key not in hs: findings.append({"severity":"Medium","title":title,"evidence":f"{key} not present in response.","recommendation":fix})
    if "server" in hs:
     http_info["server_banner"]=hs["server"]
     findings.append({"severity":"Info","title":"Server banner disclosed","evidence":hs["server"],
                      "recommendation":"Check the product/version against official vendor advisories. A banner alone does not prove outdated software."})
    if "x-powered-by" in hs:
     findings.append({"severity":"Low","title":"Technology banner disclosed","evidence":hs["x-powered-by"],
                      "recommendation":"Remove unnecessary technology-identifying headers where practical."})
  except Exception as e: http_info={"url":a.url,"error":str(e)}
 counts={x:sum(f["severity"]==x for f in findings) for x in ("High","Medium","Low","Info")}
 report={"project":"Mini Vulnerability Scanner","target":a.target,"resolved_ip":ip,
         "scan_time_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
         "ports":results,"http":http_info,"findings":findings,"summary":counts,
         "note":"Educational checks only; manually verify findings. No exploitation is performed."}
 with open(a.out+".json","w",encoding="utf-8") as f: json.dump(report,f,indent=2)
 rows="".join("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
  *(html.escape(str(f[k])) for k in ("severity","title","evidence","recommendation"))) for f in findings)
 page="""<!doctype html><meta charset="utf-8"><title>Scan Report</title>
 <style>body{font:15px Arial;background:#f3f5fa;color:#182238;margin:30px}main{max-width:1100px;margin:auto;background:white;padding:25px;border-radius:12px}table{border-collapse:collapse;width:100%}td,th{padding:11px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}th{background:#edf1fa}</style>
 <main><h1>Mini Vulnerability Scanner Report</h1><p><b>Target:</b> {}</p><p><b>UTC:</b> {}</p>
 <p>Educational checks only. Verify results manually; scan only with authorization.</p>
  <h2>Summary</h2><pre>{}</pre><h2>Port results</h2><pre>{}</pre><h2>HTTP results</h2><pre>{}</pre>
  <h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>{}</table></main>""".format(
   html.escape(a.target),report["scan_time_utc"],html.escape(json.dumps(counts,indent=2)),
   html.escape(json.dumps(results,indent=2)),html.escape(json.dumps(http_info,indent=2)),rows)
  with open(a.out+".html","w",encoding="utf-8") as f:f.write(page)
  print("\nSummary:",counts,"\nReports:",a.out+".json and "+a.out+".html")
  print("Reminder: results need manual verification; this tool does not exploit vulnerabilities.")
 if __name__=="__main__": main()
 