import os,subprocess,json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
HOST='roma-gv628rc.tailbfec94.ts.net'

def binaries(tmp_path,*,status,public_body='{"status":"live"}',refresh_exit=0):
    binpath=tmp_path/'bin';binpath.mkdir();log=tmp_path/'calls.log'
    programs={
      'tailscale':f'''#!/usr/bin/env python3
import sys
from pathlib import Path
with Path({str(log)!r}).open('a') as f:f.write('tailscale '+' '.join(sys.argv[1:])+'\\n')
if sys.argv[1:]==['funnel','status']:print({status!r})
if '--bg' in sys.argv:raise SystemExit({refresh_exit})
''',
      'curl':f'''#!/usr/bin/env python3
import sys
if any('127.0.0.1' in x for x in sys.argv):print('{{"status":"ready"}}')
else:print({public_body!r})
'''}
    for name,body in programs.items():
        p=binpath/name;p.write_text(body);p.chmod(0o700)
    env={**os.environ,'PATH':str(binpath)+':/usr/bin:/bin','NOZO_POINTER_DIR':str(tmp_path/'pointer'),'NOZO_RELAY_PUBLIC_HOST':HOST}
    return env,log

def test_watchdog_repairs_serve_only_surface(tmp_path):
    env,log=binaries(tmp_path,status=f'https://{HOST} (tailnet only)\n|-- / proxy http://127.0.0.1:8765')
    p=subprocess.run(['bash',str(ROOT/'scripts/nozo_watchdog.sh')],env=env,capture_output=True,text=True,timeout=10)
    calls=log.read_text()
    assert 'funnel --bg' in calls,f'Funnel disabled, watchdog never repaired it: exit={p.returncode}, calls={calls!r}, out={p.stdout!r}'

def test_watchdog_does_not_accept_html_with_brace(tmp_path):
    env,log=binaries(tmp_path,status=f'https://{HOST} (Funnel on)',public_body='<html><script>const x={};</script>proxy error</html>')
    p=subprocess.run(['bash',str(ROOT/'scripts/nozo_watchdog.sh')],env=env,capture_output=True,text=True,timeout=10)
    assert 'public_ok' not in p.stdout,f'HTML classified as JSON health: {p.stdout.strip()}'

def test_surface_refresh_failure_is_not_success(tmp_path):
    env,log=binaries(tmp_path,status=f'https://{HOST} (Funnel on)',refresh_exit=1)
    p=subprocess.run(['bash',str(ROOT/'scripts/ensure_tailscale_surface.sh')],env=env,capture_output=True,text=True,timeout=10)
    assert p.returncode!=0,f'failed tailscale --bg swallowed: exit 0; {p.stdout.strip()}'

def test_public_owner_login_denied_without_identity(tmp_path):
    from conftest import OWNER_PASSWORD,make_settings
    from nozo_relay.bootstrap import bootstrap
    from nozo_relay.main import create_app
    from fastapi.testclient import TestClient
    settings=make_settings(tmp_path,external_public_hosts=[HOST],allowed_hosts=[HOST],allowed_origins=['https://'+HOST])
    bootstrap(settings,owner_password=OWNER_PASSWORD)
    app=create_app(settings)
    with TestClient(app,base_url='https://'+HOST) as c:
        r=c.post('/api/v1/auth/login',json={'username':'owner','password':OWNER_PASSWORD},headers={'Origin':'https://'+HOST})
        assert r.status_code==403
        assert 'nozo_session' not in r.cookies

def test_null_origin_does_not_bypass_login_origin_boundary(env):
    from conftest import OWNER_PASSWORD
    with env.client() as c:
        r=c.post('/api/v1/auth/login',json={'username':'owner','password':OWNER_PASSWORD},headers={'Origin':'null'})
        assert r.status_code==403,f'opaque origin accepted, session minted: {r.status_code}'

def test_public_surface_denies_auditor_websocket(tmp_path):
    from conftest import OWNER_PASSWORD,make_settings
    from nozo_relay.bootstrap import bootstrap,credentials_path
    from nozo_relay.main import create_app
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    settings=make_settings(tmp_path,external_public_hosts=[HOST],allowed_hosts=[HOST])
    bootstrap(settings,owner_password=OWNER_PASSWORD)
    creds=json.loads(credentials_path(settings).read_text())
    auditor=next(a for a in creds['agents'] if a['name']=='test-auditor')
    app=create_app(settings)
    with TestClient(app,base_url='https://'+HOST) as c:
        assert c.get('/api/v1/me',headers={'Authorization':'Bearer '+auditor['key']}).status_code==403
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect('wss://'+HOST+'/ws/v1/projects/'+creds['project']['id'],headers={'Authorization':'Bearer '+auditor['key']}):
                pass
