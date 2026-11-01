"""Independent Gateway audit: real Chrome JS + real Relay use cases on disposable DB; browser network is routed."""
import json,uuid
from pathlib import Path
from datetime import UTC,datetime,timedelta
from urllib.parse import urlsplit
import pytest

playwright = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright.sync_playwright

UI='https://gateway.fixture.test'
API='https://relay.fixture.test'

@pytest.fixture
def gw(api):
    cid,key=api.make_principal('coordinator','gateway-audit-coordinator')
    until=datetime.fromtimestamp(api.clock.now_ms()/1000,UTC)+timedelta(hours=1)
    d=api.req('owner','POST',api.p('/delegations'),{'coordinator_id':cid,'allowed_actions':['task.create','task.enqueue','task.control'],'scope_ceiling':{'allowed_paths':['web/**','docs/**','tests/**'],'max_changed_files':50,'max_diff_lines':2000,'allow_autonomous':True},'valid_until':until.isoformat()})
    assert d.status_code==201,d.text
    client=api.client_for_key(key)
    config={'drop_next':False,'posts':[]}
    with sync_playwright() as pw:
      browser=pw.chromium.launch(channel='chrome',headless=True)
      page=browser.new_page()
      root=Path(__file__).resolve().parents[1]/'gateway'
      def ui(route):
        name=urlsplit(route.request.url).path.lstrip('/') or 'index.html'
        route.fulfill(status=200,body=(root/name).read_bytes(),content_type={'html':'text/html','js':'application/javascript','css':'text/css','json':'application/json'}[name.rsplit('.',1)[-1]])
      def backend(route):
        request=route.request;url=urlsplit(request.url);path=url.path+('?' + url.query if url.query else '')
        headers={k:v for k,v in request.headers.items() if k.lower() in ('authorization','content-type','idempotency-key','if-match')}
        response=client.request(request.method,path,content=request.post_data,headers=headers)
        if request.method=='POST' and url.path.endswith('/tasks'):
          config['posts'].append({'status':response.status_code,'key':headers.get('idempotency-key'),'body':request.post_data_json})
          if config['drop_next']:
            config['drop_next']=False;route.abort('connectionreset');return
        if request.method=='POST' and url.path.rstrip('/').endswith('/enqueue'):
          config.setdefault('enqueues',[]).append({'status':response.status_code,'if_match':headers.get('if-match')})
        out_headers={'Content-Type':'application/json','Access-Control-Allow-Origin':UI}
        etag=response.headers.get('etag')
        if etag: out_headers['ETag']=etag
        route.fulfill(status=response.status_code,body=response.content,headers=out_headers)
      page.route(UI+'/**',ui);page.route(API+'/**',backend)
      page.goto(UI+'/');page.locator('#connect-form [name=base]').fill(API);page.locator('#connect-form [name=key]').fill(key);page.locator('#connect-form button').click();page.locator('#app-panel').wait_for(state='visible')
      def fill(title='independent gateway task',acceptance='works'):
        for name,value in {'title':title,'requirements':'Independent disposable browser audit','acceptance':acceptance,'implementer_id':api.impl_id,'auditor_id':api.aud_id,'delegation_id':d.json()['id']}.items():page.locator(f'#task-form [name={name}]').fill(value)
      def click():
        page.locator('#btn-create-task').click()
        page.wait_for_function('!document.querySelector("#btn-create-task").disabled')
      yield page,config,fill,click,api
      browser.close()

def test_lost_response_same_payload_replays_once(gw):
    page,c,fill,click,api=gw
    fill();c['drop_next']=True;click();page.locator('#task-error').wait_for(state='visible');click();page.locator('#task-ok').wait_for(state='visible')
    assert [p['status'] for p in c['posts']]==[201,201]
    assert c['posts'][0]['key']==c['posts'][1]['key']
    assert len(api.req('owner','GET',api.p('/tasks')).json()['items'])==1

def test_pending_request_body_cannot_change_on_retry(gw):
    page,c,fill,click,api=gw
    fill('original');c['drop_next']=True;click();page.locator('#task-error').wait_for(state='visible')
    page.locator('[name=title]').fill('corrected');click()
    # An unresolved mutation must replay its original body or prevent editing until reconciled.
    assert c['posts'][-1]['status']!=409, 'Gateway reused old key with changed body and traps user in idempotency_conflict'

def test_pending_create_survives_reload_without_duplicate(gw):
    page,c,fill,click,api=gw
    fill();c['drop_next']=True;click();page.locator('#task-error').wait_for(state='visible')
    page.reload();page.locator('#app-panel').wait_for(state='visible');fill();click();page.locator('#task-ok').wait_for(state='visible')
    items=api.req('owner','GET',api.p('/tasks')).json()['items']
    assert len(items)==1,f'Unknown-outcome retry after reload created {len(items)} tasks'

def test_acceptance_is_not_silently_truncated(gw):
    page,c,fill,click,api=gw
    fill(acceptance='\n'.join(f'criterion {i}' for i in range(31)));click()
    assert not c['posts'],'31 acceptance criteria silently truncated and submitted as 30'

def test_created_task_visible_after_first_page_full(gw):
    page,c,fill,click,api=gw
    for i in range(50):
        api.clock.advance(seconds=1)
        api.create_task(title=f'older {i}')
    api.clock.advance(seconds=1)
    fill('new task must be visible');click();page.locator('#task-ok').wait_for(state='visible')
    assert 'new task must be visible' in page.locator('#task-list').inner_text(), 'Refresh only loads oldest 50 tasks, newly created task omitted'

def test_create_with_enqueue_leaves_queued_not_draft_spam(gw):
    page,c,fill,click,api=gw
    page.locator('[name=enqueue_after_create]').check()
    fill('enqueue me');click();page.locator('#task-ok').wait_for(state='visible')
    items=api.req('owner','GET',api.p('/tasks')).json()['items']
    assert len(items)==1
    assert items[0]['status']=='queued', items[0]
    assert c.get('enqueues') and c['enqueues'][-1]['status'] in (200,201)
    assert page.locator('#task-ok').inner_text().lower().find('queued')>=0

def test_complete_marks_idle_task_completed(gw):
    page,c,fill,click,api=gw
    page.locator('[name=enqueue_after_create]').uncheck()
    fill('mark me done');click();page.locator('#task-ok').wait_for(state='visible')
    page.locator('#task-list .task-item').first.click()
    page.locator('#btn-complete').wait_for(state='visible')
    page.once('dialog', lambda d: d.accept('completed via gateway test'))
    page.locator('#btn-complete').click()
    page.locator('#task-action-ok').wait_for(state='visible')
    items=api.req('owner','GET',api.p('/tasks')).json()['items']
    assert len(items)==1 and items[0]['status']=='completed', items
    opts=page.locator('#task-status-filter option').all_text_contents()
    assert 'completed' in opts and 'done' not in opts
