import json
import urllib.request

import pytest

from desk.advisories import LookupFailure, NoRedirect, OSVClient, fetch_json, summarise

PACKAGES = [{'name':'sample','version':'1.0'}]


def record(identifier='GHSA-test', severity='HIGH'):
    return {'id':identifier, 'aliases':['CVE-2026-1234'], 'summary':'Sample advisory',
        'database_specific': {'severity':severity}, 'references':[{'url':'https://example.org/advisory'},
        {'url':'javascript:alert(1)'},{'url':'https://[invalid'}], 'affected':[{'package':{
        'name':'sample','ecosystem':'PyPI'}, 'ranges':[{'events':[{'introduced':'0'},{'fixed':'1.1'}]}]}]}


@pytest.mark.parametrize('reverse', [False, True])
def test_aliases_deduplicated_and_severity_keeps_highest(reverse):
    values = [record('GHSA-test','HIGH'), record('PYSEC-test','MODERATE')]
    if reverse:
        values.reverse()
    result = summarise(values, 'sample')
    assert len(result) == 1
    assert result[0]['severity'] == 'HIGH'
    assert result[0]['ids'] == ['GHSA-test','PYSEC-test']
    assert result[0]['references'] == ['https://example.org/advisory']
    assert result[0]['fixed_markers'] == ['1.1']


def test_withdrawn_advisory_is_not_active_finding():
    value = record()
    value['withdrawn'] = '2026-01-01T00:00:00Z'
    assert summarise([value], 'sample') == []


@pytest.mark.parametrize('values', [None, {}, 'not-a-list', [{}], [None],
    [{'id':12}], [{'id':'bad/id'}], [{'id':'okay','aliases':None}],
    [{'id':'okay','affected':{}}], [{'id':'okay','database_specific':None}]])
def test_malformed_records_never_silently_disappear(values):
    with pytest.raises(ValueError):
        summarise(values, 'sample')


def test_live_batch_gets_details_and_reuses_record_within_scan():
    calls=[]
    def transport(path, payload=None, timeout=4):
        calls.append(path)
        if path.endswith('querybatch'):
            assert payload['queries'][0]['package']['ecosystem'] == 'PyPI'
            return {'results':[{'vulns':[{'id':'GHSA-test'}]} for _ in range(2)]}
        return record()
    result = OSVClient(transport).query(PACKAGES*2)
    assert [r['state'] for r in result] == ['complete','complete']
    assert calls.count('/v1/vulns/GHSA-test') == 1


def test_live_empty_result_is_verified_empty_not_failure():
    result = OSVClient(lambda *a, **k: {'results':[{}]}).query(PACKAGES)
    assert result[0]['state'] == 'complete'
    assert result[0]['records'] == []


def test_empty_package_list_does_not_send_a_request():
    def forbidden(*a, **k):
        raise AssertionError('No request expected')
    assert OSVClient(forbidden).query([]) == []


def test_wrong_advisory_identity_is_partial():
    def transport(path, payload=None, timeout=4):
        if path.endswith('querybatch'):
            return {'results':[{'vulns':[{'id':'GHSA-test'}]}]}
        return {'id':'GHSA-different'}
    result=OSVClient(transport).query(PACKAGES)[0]
    assert result['state']=='partial'
    assert result['records'][0]['id']=='GHSA-test'


@pytest.mark.parametrize('response', [{}, {'results':[]}, {'results':[None]},
    {'results':[{'vulns':None}]}])
def test_malformed_batch_marks_failed(response):
    result = OSVClient(lambda *a, **k: response).query(PACKAGES)
    assert result[0]['state'] == 'failed'


def test_failure_and_partial_details_are_visible():
    def failed(*a, **k): raise LookupFailure('timeout')
    assert OSVClient(failed).query(PACKAGES)[0]['state'] == 'failed'
    def partial(path, payload=None, timeout=4):
        if path.endswith('querybatch'):
            return {'results':[{'vulns':[{'id':'GHSA-test'}], 'next_page_token':'next'}]}
        raise LookupFailure('timeout')
    result = OSVClient(partial).query(PACKAGES)[0]
    assert result['state'] == 'partial'
    assert result['records'][0]['id'] == 'GHSA-test'
    assert 'pagination' in result['reason']


def test_malformed_details_preserve_known_id_as_partial():
    def transport(path, payload=None, timeout=4):
        if path.endswith('querybatch'):
            return {'results':[{'vulns':[{'id':'GHSA-test'}]}]}
        return {'id':'GHSA-test','aliases':None}
    result = OSVClient(transport).query(PACKAGES)[0]
    assert result['state'] == 'partial'
    assert result['records'][0]['id'] == 'GHSA-test'


def test_budget_never_turns_unfetched_details_into_complete():
    times=iter([0,19])
    client=OSVClient(lambda *a, **k: {'results':[{'vulns':[{'id':'GHSA-test'}]}]}, clock=lambda:next(times))
    assert client.query(PACKAGES)[0]['state'] == 'partial'


def test_invalid_record_id_cannot_be_used_as_a_url():
    result = OSVClient(lambda *a, **k: {'results':[{'vulns':[{'id':'../../etc/passwd'}]}]}).query(PACKAGES)
    assert result[0]['state'] == 'partial'
    assert result[0]['records'] == []


def test_detail_limit_and_package_record_limit_are_partial():
    calls=[]
    def transport(path, payload=None, timeout=4):
        calls.append(path)
        if path.endswith('querybatch'):
            return {'results':[{'vulns':[{'id':f'GHSA-{i}'} for i in range(110)]}]}
        return {'id':path.rsplit('/',1)[-1]}
    result=OSVClient(transport).query(PACKAGES)[0]
    assert result['state'] == 'partial'
    assert len(result['records']) == 100
    assert len(calls) == 61


@pytest.mark.parametrize('path', ['/v1/vulns/../../x','https://evil.example','/v1/query'])
def test_transport_accepts_only_fixed_routes(path):
    with pytest.raises(LookupFailure): fetch_json(path)


def test_redirects_are_blocked():
    with pytest.raises(LookupFailure):
        NoRedirect().redirect_request(None,None,302,'',{},'http://127.0.0.1/private')


def test_response_limit_and_malformed_json(monkeypatch):
    class Response:
        def __init__(self, data): self.data=data
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def read(self,n): return self.data[:n]
    class Opener:
        def __init__(self,data): self.data=data
        def open(self,*a,**k): return Response(self.data)
    for content in (b'x'*(2*1024*1024+1), b'{bad', b'[]'):
        monkeypatch.setattr(urllib.request,'build_opener',lambda *a:Opener(content))
        with pytest.raises(LookupFailure): fetch_json('/v1/querybatch', {'queries':[]})
    monkeypatch.setattr(urllib.request,'build_opener',lambda *a:Opener(json.dumps({'results':[]}).encode()))
    assert fetch_json('/v1/querybatch', {'queries':[]}) == {'results':[]}
