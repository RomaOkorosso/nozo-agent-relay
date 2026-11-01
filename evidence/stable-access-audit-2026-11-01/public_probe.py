import json,socket,ssl,http.client
from pathlib import Path
out=Path('/tmp/nozo-stable-audit-ozjmwsl2');host='roma-gv628rc.tailbfec94.ts.net'
ip=next(a['data'] for a in json.loads((out/'public-dns.json').read_text())['Answer'] if a['type']==1)
key=json.loads(Path('/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay/data/clients/codex_credentials.json').read_text())['key']
cases=[('health','GET','/api/v1/health/live',{}),('agents_public','GET','/api/v1/agents',{}),('forged_identity','GET','/api/v1/agents',{'Tailscale-User-Login':'audit-forged@example.invalid','Tailscale-User-Name':'audit-forged'}),('auditor_denied_public','GET','/api/v1/me',{'Authorization':'Bearer '+key,'Origin':'https://romaokorosso.github.io'}),('preflight','OPTIONS','/api/v1/projects/default/tasks',{'Origin':'https://romaokorosso.github.io','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,content-type,idempotency-key'})]
results=[]
for name,method,path,headers in cases:
 try:
  c=http.client.HTTPSConnection(host,timeout=10)
  c.sock=ssl.create_default_context().wrap_socket(socket.create_connection((ip,443),timeout=10),server_hostname=host)
  c.request(method,path,headers=headers);r=c.getresponse();data=r.read()
  results.append({'case':name,'public_ip':ip,'status':r.status,'content_type':r.getheader('content-type'),'acao':r.getheader('access-control-allow-origin'),'body':data.decode()[:500]});c.close()
 except Exception as e:results.append({'case':name,'error':type(e).__name__,'detail':str(e)})
(out/'public-probe.json').write_text(json.dumps(results,indent=2));print(json.dumps(results))
