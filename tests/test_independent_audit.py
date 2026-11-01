"""Independent correct-behavior assertions. Disposable audit copy only."""
import json
import sqlite3
import uuid
from datetime import datetime, UTC, timedelta
import pytest
from nozo_relay import backup
from nozo_relay.keymint import mint_key
from sqlalchemy.orm import Session


def test_delegation_cannot_widen_file_glob(api):
    cid, key = api.make_principal('coordinator', 'independent-coordinator')
    until = datetime.fromtimestamp(api.clock.now_ms()/1000, UTC)+timedelta(hours=1)
    r=api.req('owner','POST',api.p('/delegations'),{'coordinator_id':cid,'allowed_actions':['task.create','task.enqueue'],'scope_ceiling':{'allowed_paths':['src/*.py'],'max_changed_files':5,'max_diff_lines':200,'allow_autonomous':True},'valid_until':until.isoformat()})
    assert r.status_code==201, r.text
    body=api.task_body(delegation_id=r.json()['id'],scope={'allowed_paths':['src/*.sh'],'denied_paths':[],'max_changed_files':5,'max_diff_lines':200,'allow_new_dependencies':False})
    r=api.req(api.client_for_key(key),'POST',api.p('/tasks'),body)
    assert r.status_code==403, f'out-of-ceiling .sh task accepted: HTTP {r.status_code}'


def test_project_policy_cannot_widen_file_glob(api):
    version=api.req('owner','GET',api.p()).json()['version']
    r=api.req('owner','PUT',api.p('/policy'),{'policy':{'scope_ceiling':{'allowed_paths':['src/*.py'],'max_changed_files':5,'max_diff_lines':200}},'reason':'independent audit'},if_match=version)
    assert r.status_code==200,r.text
    r=api.req('owner','POST',api.p('/tasks'),api.task_body(scope={'allowed_paths':['src/*.sh'],'denied_paths':[],'max_changed_files':5,'max_diff_lines':200,'allow_new_dependencies':False}))
    assert r.status_code==422, f'project ceiling bypass: HTTP {r.status_code}'


def test_incomplete_backup_must_not_restore(api,env,tmp_path):
    r=api.clients['impl'].post(api.p('/artifacts'),content=b'independent evidence',headers={'Idempotency-Key':str(uuid.uuid4())})
    assert r.status_code==201,r.text
    aid=r.json()['id']
    (env.settings.artifacts_dir/aid[:2]/aid).unlink() # simulated loss of this disposable fixture only
    dest=tmp_path/'backup'
    manifest=backup.create_backup(env.settings,dest,env.clock)
    assert manifest['complete'] is False
    with pytest.raises(backup.BackupError):
        backup.restore_backup(dest,tmp_path/'restored',env.clock)


def test_mint_commit_failure_does_not_leave_key_file(api,env,monkeypatch):
    def fail(self):
        raise sqlite3.OperationalError('injected commit failure')
    monkeypatch.setattr(Session,'commit',fail)
    with pytest.raises(sqlite3.OperationalError):
        mint_key(env.settings,api.impl_id,clock=env.clock)
    files=list((env.settings.data_dir/'minted_keys').glob('*.json'))
    assert files==[], f'{len(files)} key file remains despite rolled back credential'


def test_disk_full_is_explicit_retryable_failure(api,monkeypatch):
    from sqlalchemy import event
    engine=api.app.state.engine
    def full(conn,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('INSERT INTO MESSAGES'):
            raise sqlite3.OperationalError('database or disk is full')
    event.listen(engine,'before_cursor_execute',full)
    client=api.clients['impl']
    client.raise_server_exceptions=False
    # TestClient transport flag is the actual exception boundary.
    client._transport.raise_server_exceptions=False
    key=str(uuid.uuid4()); body={'client_message_id':str(uuid.uuid4()),'kind':'note','body':'disk-full sentinel'}
    try:
        r=api.req('impl','POST',api.p('/messages'),body,idem=key)
    finally:
        event.remove(engine,'before_cursor_execute',full)
    retry=api.req('impl','POST',api.p('/messages'),body,idem=key)
    assert retry.status_code==201,retry.text
    assert r.status_code==503, f'disk-full returned {r.status_code}: {r.text}'


def test_sandbox_cannot_chmod_protected_host_file(tmp_path):
    import os, subprocess, stat
    from nozo_relay.runner.sandbox import RunDirs,Limits,build_policy,interpreter_prefix,launch_shim
    dirs=RunDirs(*(tmp_path/n for n in ('workspace','ro','out','home','tmp')))
    for d in (dirs.workspace,dirs.ro,dirs.out,dirs.home,dirs.tmp): d.mkdir()
    sentinel=tmp_path/'protected-owner-file'; sentinel.write_text('disposable sentinel'); sentinel.chmod(0o600)
    exe,_=interpreter_prefix()
    policy=build_policy(argv=[str(exe),'-I','-c',f'import os; os.chmod({str(sentinel)!r},0o644)'],dirs=dirs,extra_ro=[],net_mode='none',net_ports=[],limits=Limits(),cgroup_procs=None,memory_via_rlimit=False,nproc_limit=None)
    path=tmp_path/'policy.json'; path.write_text(json.dumps(policy))
    child=launch_shim(path,env={'PATH':'/usr/bin:/bin'},cwd=dirs.workspace,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    ready,why=child.wait_ready()
    assert ready,why
    child.proc.wait(timeout=10)
    mode=stat.S_IMODE(sentinel.stat().st_mode)
    assert mode==0o600,f'protected host file mode changed to {oct(mode)} (child exit {child.proc.returncode})'


def test_independent_concurrent_claim_and_cancel_fence(api):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    task=api.queued_task()
    barrier=threading.Barrier(2)
    def claim(i):
        c=api.client_for_key(api.keys['impl'])
        barrier.wait(timeout=10)
        return api.req(c,'POST',api.p('/jobs/claim'),{'stage':'implement','claim_request_id':str(uuid.uuid4()),'runner_instance_id':f'independent-{i}'})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(claim,range(2)))
    assert sorted(r.status_code for r in results)==[200,204]
    run=next(r.json() for r in results if r.status_code==200)
    api.start('impl',run)
    stop=api.control(task['id'],'cancel')
    assert stop.status_code==202
    assert api.get_task(task['id'])['status']=='stop_requested'
    stale=api.submit_impl(run,expect=None)
    assert stale.status_code==409
    assert api.get_task(task['id'])['status']!='completed'


def test_independent_create_replay_conflict_and_restart(api):
    key=str(uuid.uuid4()); body=api.task_body(title='independent replay')
    first=api.req('owner','POST',api.p('/tasks'),body,idem=key)
    assert first.status_code==201
    restarted=api.restart()
    replay=restarted.req('owner','POST',api.p('/tasks'),body,idem=key)
    assert replay.status_code==201 and replay.json()==first.json()
    conflict=restarted.req('owner','POST',api.p('/tasks'),{**body,'title':'changed'},idem=key)
    assert conflict.status_code==409


def test_independent_not_run_cannot_complete(api):
    task=api.queued_task(); api.implement(task['id'])
    run=api.claim('aud'); api.start('aud',run)
    r=api.submit_audit(run,'PASS',expect=None,checks=[{'id':'required','command_label':'independent check','status':'not_run'}])
    assert r.status_code==422
    assert api.get_task(task['id'])['status']=='reviewing'


def test_unrelated_supervisor_cannot_confirm_another_run(api):
    task=api.queued_task(); run=api.claim(runner='original-supervisor'); api.start('impl',run)
    stop=api.control(task['id'],'cancel').json()['control']
    # Registered only AFTER this run started; it has never owned or supervised the run.
    _,key=api.make_principal('runner','unrelated-supervisor')
    r=api.req(api.client_for_key(key),'POST',api.p(f"/runs/{run['run_id']}/stopped"),{'control_id':stop['id'],'target_epoch':run['lease_epoch'],'process_tree_absent':True,'receipt':'not the owning supervisor'})
    assert r.status_code in (403,404),f'unrelated supervisor accepted: HTTP {r.status_code}; task={api.get_task(task["id"])["status"]}'


def test_supervisor_cannot_read_project_chat(api):
    r=api.req('owner','POST',api.p('/messages'),{'client_message_id':str(uuid.uuid4()),'kind':'note','body':'owner project discussion'})
    assert r.status_code==201
    _,key=api.make_principal('runner','metadata-only-supervisor')
    r=api.req(api.client_for_key(key),'GET',api.p('/messages'))
    assert r.status_code in (403,404),f'supervisor can read project messages: HTTP {r.status_code}'
