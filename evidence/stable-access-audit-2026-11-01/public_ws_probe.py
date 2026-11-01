import json,socket
from pathlib import Path
from websockets.sync.client import connect
out=Path('/tmp/nozo-stable-audit-ozjmwsl2');host='roma-gv628rc.tailbfec94.ts.net'
ip=next(a['data'] for a in json.loads((out/'public-dns.json').read_text())['Answer'] if a['type']==1)
c=json.loads(Path('/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay/data/clients/codex_credentials.json').read_text())
try:
 with connect('wss://'+host+'/ws/v1/projects/'+c['project']['id']+'?after_seq=0',sock=socket.create_connection((ip,443),timeout=10),additional_headers={'Authorization':'Bearer '+c['key']},open_timeout=10,close_timeout=3) as ws:
  frame=json.loads(ws.recv(timeout=8))
  result={'public_ip':ip,'handshake':ws.response.status_code,'credential_kind':'auditor','frame_type':frame.get('type'),'frame_has_project_data':bool(frame.get('data') or frame.get('payload'))}
except Exception as e:result={'public_ip':ip,'error':type(e).__name__,'detail':str(e)}
(out/'public-ws-probe.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
