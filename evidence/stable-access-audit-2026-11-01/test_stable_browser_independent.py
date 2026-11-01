import json
from pathlib import Path
from urllib.parse import urlsplit
import pytest
from playwright.sync_api import sync_playwright,expect
ROOT=Path(__file__).resolve().parents[1]/'gateway'
UI='https://stable-gateway.fixture.test'
OLD='https://old-relay.fixture.test'
NEW='https://new-relay.fixture.test'
PID='11111111-1111-4111-8111-111111111111'

@pytest.fixture
def browser():
    with sync_playwright() as pw:
        b=pw.chromium.launch(channel='chrome',headless=True)
        yield b
        b.close()

def setup(browser,*,saved=OLD,old_down=False,reject_messages=False):
    context=browser.new_context();page=context.new_page();calls=[]
    page.clock.install()
    if saved:
        page.add_init_script('sessionStorage.setItem("nozo_gw_base",'+json.dumps(saved)+');sessionStorage.setItem("nozo_gw_key","SENTINEL_FIXTURE_ONLY");')
    state={'down':old_down,'reject':reject_messages,'drop_message':False,'message_ids':set()}
    def route_handler(route):
        req=route.request;url=urlsplit(req.url);calls.append({'url':req.url,'method':req.method})
        if req.url.startswith(UI):
            name=url.path.lstrip('/') or 'index.html'
            if name=='pointer.json':route.fulfill(json={'relay_base':NEW});return
            route.fulfill(body=(ROOT/name).read_bytes(),content_type={'html':'text/html','js':'application/javascript','css':'text/css'}[name.rsplit('.',1)[-1]]);return
        if req.url.startswith(OLD) and state['down']:route.abort('connectionreset');return
        if url.path.endswith('/me'):
            route.fulfill(json={'principal':{'display_name':'fixture','kind':'coordinator'},'memberships':[{'project_id':PID,'name':'fixture','role':'coordinator'}]});return
        if req.method=='POST' and url.path.endswith('/messages'):
            if state['reject']:route.fulfill(status=422,json={'error':{'code':'validation_error','message':'Message too large'}});return
            key=req.headers['idempotency-key'];state['message_ids'].add(key)
            if state['drop_message']:state['drop_message']=False;route.abort('connectionreset');return
            route.fulfill(status=201,json={'id':key});return
        route.fulfill(json={'items':[],'next_cursor':None})
    page.route('**/*',route_handler);page.goto(UI+'/')
    return context,page,calls,state

def test_startup_uses_current_pointer_if_saved_endpoint_dead(browser):
    ctx,page,calls,state=setup(browser,old_down=True)
    page.locator('#connect-error').wait_for(state='visible')
    page.clock.run_for(16000)
    assert any(c['url']==NEW+'/api/v1/me' for c in calls),'Valid current pointer ignored on startup; only dead saved endpoint tried, polling never starts'
    assert page.locator('#app-panel').is_visible()
    ctx.close()

def test_existing_connection_recovers_via_pointer(browser):
    ctx,page,calls,state=setup(browser)
    page.locator('#app-panel').wait_for(state='visible')
    expect(page.locator('#task-list')).to_contain_text('Нет задач')
    state['down']=True
    page.clock.run_for(16000)
    page.wait_for_function('sessionStorage.getItem("nozo_gw_base") === '+json.dumps(NEW),timeout=5000)
    expect(page.locator('#conn-chip')).to_have_attribute('data-state','connected')
    assert any(c['url'].startswith(NEW+'/api/v1/projects/') for c in calls)
    ctx.close()

def test_message_drop_and_reload_keeps_same_operation(browser):
    ctx,page,calls,state=setup(browser,saved=NEW)
    page.locator('#app-panel').wait_for(state='visible');page.locator('#msg-form textarea').fill('fixture message');state['drop_message']=True
    page.locator('#btn-send-msg').click();page.locator('#msg-error').wait_for(state='visible')
    page.reload();page.locator('#app-panel').wait_for(state='visible');page.locator('#btn-send-msg').click();page.locator('#msg-ok').wait_for(state='visible')
    assert len(state['message_ids'])==1
    ctx.close()

def test_rejected_message_can_be_cleared_by_documented_ui_steps(browser):
    ctx,page,calls,state=setup(browser,saved=NEW,reject_messages=True)
    page.locator('#app-panel').wait_for(state='visible');page.locator('#msg-form textarea').fill('rejected fixture message');page.locator('#btn-send-msg').click();page.locator('#msg-error').wait_for(state='visible')
    page.locator('#msg-form textarea').fill('corrected message');page.locator('#btn-send-msg').click()
    assert 'отключитесь' in page.locator('#msg-error').inner_text()
    page.locator('#msg-form textarea').fill('');page.locator('#btn-disconnect').click()
    page.locator('#connect-form [name=base]').fill(NEW);page.locator('#connect-form [name=key]').fill('SENTINEL_FIXTURE_ONLY');page.locator('#connect-form button').click();page.locator('#app-panel').wait_for(state='visible')
    pending=page.evaluate('sessionStorage.getItem("nozo_gw_pending_msg")')
    assert pending is None,'UI-prescribed clear + disconnect/reconnect retains rejected immutable message; user cannot send corrected text'
    ctx.close()
