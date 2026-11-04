"""Correlaciones con datos sinteticos, sin acceso al Excel original."""
from datetime import datetime, timedelta
import pandas as pd
import pytest
from detection import detect, Parameters, risk_level
from importer import COLUMNS

BASE = datetime(2026, 10, 23, 9)
def event(identifier, seconds, event_id, **changes):
    row = dict.fromkeys(COLUMNS, '')
    row.update(Log_ID=identifier, Timestamp=BASE+timedelta(seconds=seconds), Event_ID=event_id,
               Hostname='HOST', User='user', Source_IP='10.0.0.1', Log_Source='Security',
               Result='Failure' if event_id == '4625' else 'Success', Severity='Informational')
    row.update(changes)
    return row

def run(rows, **params):
    frame = pd.DataFrame(rows, columns=COLUMNS)
    frame.index += 2
    before = frame.copy(deep=True)
    result = detect(frame, Parameters(**params))
    pd.testing.assert_frame_equal(frame, before)
    return result

def auth():
    return [event(f'F{i}', second, '4625') for i, second in enumerate([0, 60, 120, 300])] + [event('S',900,'4624')]

def transfer():
    return [event('A',0,'4688',Process_CommandLine='7z.exe a archive.7z files')] + [
        event(f'P{i}',second,'PROXY_ACCESS',Log_Source='Proxy',Result='Allowed',Process_CommandLine='bytes_out=40000000 uri=/upload')
        for i, second in enumerate([1,300,600])]

def service():
    return [event('I',0,'7045',Log_Source='System',Process_CommandLine='ServiceName=Example; ImagePath="C:\\ProgramData\\app.exe" -s'),
            event('E',1800,'4688',Process_CommandLine='c:\\programdata\\APP.exe -s')]

@pytest.mark.parametrize('builder,rule',[(auth,'AUTH'),(transfer,'TRANSFER'),(service,'SERVICE')])
def test_inclusive_boundaries(builder,rule):
    assert run(builder()).findings[0].rule == rule
    rows=builder()
    rows[-1]['Timestamp'] += timedelta(seconds=1)
    assert not run(rows).findings

@pytest.mark.parametrize('builder',[auth,transfer,service])
def test_no_temporal_only_match(builder):
    rows=builder()
    rows[-1]['Hostname']='OTHER'
    assert not run(rows).findings

@pytest.mark.parametrize('key',['User','Source_IP'])
@pytest.mark.parametrize('builder',[auth,transfer])
def test_identity_mismatch(builder,key):
    rows=builder()
    rows[-1][key]='other'
    assert not run(rows).findings

def test_auth_window_context_and_no_reuse():
    rows=auth()
    rows[0]['Timestamp'] -= timedelta(seconds=1)
    assert not run(rows).findings
    rows=auth()+[event('P',901,'4672'),event('S2',902,'4624')]
    findings=run(rows).findings
    assert len(findings)==1
    assert findings[0].context[0]['Log_ID']=='P'
    assert findings[0].risk=='medio'
    rows[-2]['Hostname']='OTHER'
    assert not run(rows).findings[0].context

def test_proxy_incomplete_bytes_and_compression_semantics():
    rows=transfer()
    rows[-1]['Process_CommandLine']='bytes_out=unknown'
    finding=run(rows).findings[0]
    assert finding.metrics['bytes_total'] is None
    assert finding.metrics['bytes_known_sum']==80000000
    assert finding.risk=='medio'
    rows[0]['Process_CommandLine']='7z.exe l archive.7z'
    assert not run(rows).findings

def test_service_path_and_no_task_causality():
    rows=service()
    assert run(rows).findings[0].risk=='bajo'
    rows.append(event('T',10,'4698',Process_CommandLine='TaskName=Example'))
    assert not run(rows).findings[0].context
    rows[1]['Process_CommandLine']='C:\\Other\\app.exe'
    assert not run(rows).findings

@pytest.mark.parametrize('builder',[auth,transfer,service])
def test_wrong_source_and_missing_entities(builder):
    rows=builder()
    rows[-1]['Log_Source']='Other'
    assert not run(rows).findings
    rows=builder()
    for row in rows:
        row['Hostname']='-'
    assert not run(rows).findings

def test_invalid_dates_duplicate_ids_and_parameters():
    rows=auth()
    rows[-1]['Timestamp']=None
    assert len(run(rows).excluded_rows)==1
    rows=auth()
    rows[1]['Log_ID']=rows[0]['Log_ID']
    assert len(run(rows).excluded_rows)==2
    assert not run(rows).findings
    with pytest.raises(ValueError):
        Parameters(min_failures=0)
    assert [risk_level(n) for n in [1,2,3]]==['bajo','medio','alto']

@pytest.mark.parametrize('builder',[auth,transfer,service])
def test_events_must_be_strictly_subsequent(builder):
    rows=builder()
    rows[-1]['Timestamp']=rows[0]['Timestamp']
    assert not run(rows).findings

def test_configurable_thresholds_and_partial_high_volume():
    assert not run(auth(),min_failures=5).findings
    assert not run(transfer(),min_proxy=4).findings
    assert run(transfer(),high_bytes=120000000).findings[0].risk=='alto'
    assert run(transfer(),high_bytes=120000001).findings[0].risk=='medio'
    rows=transfer()
    rows[1]['Process_CommandLine']='bytes_out=120000000'
    rows[2]['Process_CommandLine']='bytes_out=invalid'
    finding=run(rows).findings[0]
    assert finding.risk=='alto'
    assert finding.metrics['bytes_total'] is None
