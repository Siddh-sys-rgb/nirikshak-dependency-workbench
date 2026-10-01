import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from desk import create_app
from desk.advisories import now


def test_public_health_bootstrap_and_security_headers(client):
    assert client.get('/api/health').json['status']=='ok'
    response=client.get('/api/bootstrap')
    assert 'nirikshak_session=' in response.headers['Set-Cookie']
    assert 'HttpOnly' in response.headers['Set-Cookie']
    assert 'SameSite=Strict' in response.headers['Set-Cookie']
    assert response.headers['Cache-Control']=='no-store'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert client.get('/').status_code==200


def test_mutations_require_csrf_and_same_origin(client,token):
    data={'text':'Jinja2==3.1.4'}
    assert client.post('/api/scans',json=data).status_code==403
    assert client.post('/api/scans',json=data,headers={'X-CSRF-Token':'wrong'}).status_code==403
    assert client.post('/api/scans',json=data,headers={'X-CSRF-Token':'é'}).status_code==403
    assert client.post('/api/scans',json=data,headers={**token,'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/scans',json=data,headers={**token,'Origin':'http://localhost'}).status_code==201


def test_invalid_host_rejected(client):
    assert client.get('/api/health',headers={'Host':'evil.example'}).status_code==400


def test_scan_saved_exported_and_immutable(client,token):
    response=client.post('/api/scans',json={'name':'Aarav <script>alert(1)</script>','text':'Jinja2==3.1.4'},headers=token)
    assert response.status_code==201
    report=response.json
    assert report['summary']['findings']==3
    assert client.get('/api/scans/'+report['id']).json==report
    exported=client.get('/api/scans/'+report['id']+'/export')
    assert json.loads(exported.data)==report
    assert 'attachment' in exported.headers['Content-Disposition']
    assert client.put('/api/scans/'+report['id'],json={},headers=token).status_code==405
    assert client.delete('/api/scans/'+report['id'],headers=token).status_code==405


@pytest.mark.parametrize('payload', [[], None, {'name':'' ,'text':'x==1'},
    {'name':12,'text':'x==1'}, {'name':'x'*81,'text':'x==1'}, {'name':'x\ny','text':'x==1'},
    {'mode':'unknown','text':'x==1'}, {'text':None}, {'text':'# no packages'},
    {'mode':'live','text':'x==1'}, {'mode':'live','text':'x==1','live_consent':'true'}])
def test_invalid_submissions(client,token,payload):
    response=client.post('/api/scans',json=payload,headers=token)
    # None encodes no JSON body in Flask's test client; upload path rejects it.
    assert response.status_code==422


def test_live_consent_creates_evidence_and_cache(client,token):
    response=client.post('/api/scans',json={'text':'unfamiliar==1.0','mode':'live','live_consent':True},headers=token)
    assert response.status_code==201
    assert response.json['summary']['checked']==1
    assert response.json['packages'][0]['source']=='OSV live lookup'
    offline=client.post('/api/scans',json={'text':'unfamiliar==1.0'},headers=token)
    assert offline.json['packages'][0]['source']=='OSV live cache'


def test_live_failure_saved_as_unchecked_snapshot(client,token,app):
    class Failure:
        def query(self,packages):
            return [{'state':'failed','records':[],'retrieved_at':None,'reason':'Connection unavailable'} for p in packages]
    app.config['OSV_CLIENT']=Failure()
    response=client.post('/api/scans',json={'text':'Jinja2==3.1.4','mode':'live','live_consent':True},headers=token)
    assert response.status_code==201
    assert response.json['summary']['checked']==0
    assert response.json['summary']['complete'] is False


def test_cooldown_explicit_retry_error(client,token,app):
    app.config['LIVE_COOLDOWN']=5
    data={'text':'somepkg==1','mode':'live','live_consent':True}
    assert client.post('/api/scans',json=data,headers=token).status_code==201
    assert client.post('/api/scans',json=data,headers=token).status_code==429


def test_concurrent_live_query_returns_busy_without_duplicate_network_calls(app):
    started, finish = threading.Event(), threading.Event()
    class BlockingProvider:
        def query(self,packages):
            started.set()
            assert finish.wait(3)
            return [{'state':'complete','records':[],'retrieved_at':now(),'reason':''} for p in packages]
    app.config['OSV_CLIENT']=BlockingProvider()
    data={'text':'sample==1','mode':'live','live_consent':True}
    def submit():
        client=app.test_client()
        token=client.get('/api/bootstrap').json['csrf']
        return client.post('/api/scans',json=data,headers={'X-CSRF-Token':token})
    with ThreadPoolExecutor(max_workers=2) as executor:
        first=executor.submit(submit)
        try:
            assert started.wait(2)
            assert submit().status_code==429
        finally:
            finish.set()
        assert first.result().status_code==201


def test_scan_limit_is_explicit(client,token,app):
    from desk.storage import connect, get_scan, save_scan
    with connect(app.config['DATA_DIR']+'/workbench.db') as db:
        report=get_scan(db,'demo-baseline')
        for index in range(198):
            report['id']=f'capacity-{index}'
            save_scan(db,report)
    response=client.post('/api/scans',json={'text':'sample==1'},headers=token)
    assert response.status_code==422
    assert '200' in response.json['error']


def test_unexpected_provider_error_is_not_exposed_or_saved_as_clean(client,token,app):
    class BrokenProvider:
        def query(self,packages):
            raise RuntimeError('private-provider-internals')
    app.config['OSV_CLIENT']=BrokenProvider()
    response=client.post('/api/scans',json={'text':'sample==1','mode':'live','live_consent':True},headers=token)
    assert response.status_code==500
    assert 'private-provider' not in response.json['error']
    assert len(client.get('/api/scans').json['scans'])==2


def test_upload_utf8_manifest_and_bom(client,token):
    response=client.post('/api/scans',data={'manifest':(io.BytesIO(b'\xef\xbb\xbfJinja2==3.1.4'),'requirements.txt'),'name':'Imported'},headers=token)
    assert response.status_code==201
    assert response.json['summary']['findings']==3


@pytest.mark.parametrize('content,filename', [(b'Jinja2==3.1.4','script.py'),(b'\xff','requirements.txt'),(b'x'*32769,'requirements.txt')])
def test_invalid_uploads(client,token,content,filename):
    assert client.post('/api/scans',data={'manifest':(io.BytesIO(content),filename)},headers=token).status_code==422


def test_overall_request_limit(client,token):
    assert client.post('/api/scans',data=b'x'*65537,headers=token).status_code==413


def test_comparison_defaults_missing_or_unknown(client):
    result=client.get('/api/compare?before=demo-baseline&after=demo-update')
    assert result.status_code==200
    assert len(result.json['resolved'])==3
    assert client.get('/api/compare').status_code==422
    assert client.get('/api/compare?before=unknown&after=demo-update').status_code==404
    assert client.get('/api/scans/unknown').status_code==404


def test_no_demo_still_has_bundled_cache(tmp_path):
    app=create_app({'DATA_DIR':str(tmp_path),'SEED_DEMO':False,'SECRET_KEY':'tests'})
    client=app.test_client()
    assert client.get('/api/scans').json['scans']==[]
    token=client.get('/api/bootstrap').json['csrf']
    response=client.post('/api/scans',json={'text':'Jinja2==3.1.6'},headers={'X-CSRF-Token':token})
    assert response.json['summary']['checked']==1


def test_session_key_persists_across_restart(tmp_path):
    first=create_app({'DATA_DIR':str(tmp_path),'SEED_DEMO':False})
    second=create_app({'DATA_DIR':str(tmp_path),'SEED_DEMO':False})
    assert first.config['SECRET_KEY']==second.config['SECRET_KEY']
    assert (tmp_path/'session.key').stat().st_mode & 0o777 == 0o600
