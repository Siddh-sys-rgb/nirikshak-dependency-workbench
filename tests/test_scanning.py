from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from desk.advisories import now
from desk.scanning import compare, freshness, scan
from desk.storage import cached, connect, get_scan, save_cache


@pytest.fixture
def db(app):
    with connect(app.config['DATA_DIR']+'/workbench.db') as connection:
        yield connection


def test_bundled_source_provenance_and_alias_counts(db):
    baseline=get_scan(db,'demo-baseline')
    updated=get_scan(db,'demo-update')
    assert baseline['summary']['checked']==2
    assert baseline['summary']['findings']==4
    assert updated['summary']['findings']==5
    assert all(p['source']=='Bundled OSV snapshot' and p['retrieved_at'] for p in baseline['packages'])
    diff=compare(baseline,updated)
    assert [len(diff[k]) for k in ('new','resolved','unchanged')] == [4,3,1]
    assert diff['coverage']['compared_packages']==['jinja2','requests']


def test_unknown_package_not_clean(db):
    report=scan(db,'not-in-the-cache==1.0','Unknown')
    assert report['packages'][0]['state']=='unverified'
    assert report['summary']['checked']==0
    assert report['summary']['complete'] is False
    assert report['summary']['findings']==0


@pytest.mark.parametrize('response', [[], {'vulns':None}, {'vulns':[{}]},
    {'vulns':[{'id':'test','aliases':None}]}, {'vulns':[{'id':'test','affected':[None]}]}])
def test_invalid_cache_cannot_be_verified_clean(db,response):
    save_cache(db,'test','1',now(),response)
    report=scan(db,'test==1','Malformed')
    assert report['packages'][0]['state']=='failed'
    assert report['summary']['checked']==0
    assert report['summary']['complete'] is False


def test_paginated_cache_not_complete(db):
    save_cache(db,'test','1',now(),{'vulns':[], 'next_page_token':'next'})
    assert scan(db,'test==1','Partial')['packages'][0]['state']=='partial'


def test_unsupported_only_manifest_is_reported_as_gap(db):
    report=scan(db,'-r secrets.txt','Not executed')
    assert report['summary']['unsupported']==1
    assert report['summary']['complete'] is False
    assert not report['packages']


def test_conflicting_version_is_not_comparison_coverage(db):
    report=scan(db,'Jinja2==3.1.6\nJinja2==3.1.4','Ambiguous')
    assert report['packages'][0]['state']=='partial'
    diff=compare(get_scan(db,'demo-baseline'),report)
    assert not diff['resolved']
    assert diff['coverage']['unverified_packages']==['jinja2']


def test_live_success_updates_cache_without_rewriting_old_snapshot(db,app):
    before=get_scan(db,'demo-baseline')
    report=scan(db,'Jinja2==3.1.4','New evidence','live',app.config['OSV_CLIENT'])
    assert report['packages'][0]['state']=='complete'
    assert cached(db,'jinja2','3.1.4')['response']=={'vulns':[]}
    assert get_scan(db,'demo-baseline')==before


def test_failed_live_lookup_does_not_destroy_valid_cache(db):
    class Failure:
        def query(self,packages):
            return [{'state':'failed','records':[],'retrieved_at':now(),'reason':'timeout'} for p in packages]
    original=cached(db,'jinja2','3.1.4')
    report=scan(db,'Jinja2==3.1.4','Failed refresh','live',Failure())
    assert report['packages'][0]['state']=='failed'
    assert cached(db,'jinja2','3.1.4')==original


def test_removed_dependency_is_not_declared_resolved(db):
    before=get_scan(db,'demo-baseline')
    after=scan(db,'requests==2.32.4','Removed template dependency')
    diff=compare(before,after)
    assert diff['removed_packages']==['jinja2']
    assert not diff['resolved']


def test_failed_after_lookup_cannot_resolve_old_findings(db):
    before=get_scan(db,'demo-baseline')
    after=deepcopy(before)
    after['packages'][0]['state']='failed'
    after['packages'][0]['findings']=[]
    diff=compare(before,after)
    assert not diff['resolved']
    assert diff['coverage']['unverified_packages']==['jinja2']


def test_added_package_reported_outside_findings_comparison(db):
    before=scan(db,'Jinja2==3.1.6','Before')
    after=get_scan(db,'demo-update')
    diff=compare(before,after)
    assert diff['added_packages']==['requests']
    assert not diff['new']


def test_same_snapshot_has_only_unchanged_findings(db):
    report=get_scan(db,'demo-baseline')
    result=compare(report,report)
    assert not result['new'] and not result['resolved']
    assert len(result['unchanged'])==4


@pytest.mark.parametrize('retrieved', [None,'invalid','2026-01-01T00:00:00'])
def test_unknown_freshness_is_explicit(retrieved):
    assert freshness(retrieved)=={'age_seconds':None,'freshness':'unknown'}


def test_stale_timestamp_is_not_changed_to_now():
    value=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
    result=freshness(value)
    assert result['freshness']=='stale'
    assert result['age_seconds']>=172799
