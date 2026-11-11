"""Replayable multi-validator integration against hosted Studio, using real web and LLM calls."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
import urllib.request
from eth_account import Account
from scripts.envelopes import canonical, source_manifest, request_envelope
from scripts.studio import Studio, atomic_json


def credentials():
    stored = json.loads(Path('.secrets/credentials.json').read_text()) if Path('.secrets/credentials.json').exists() else {}
    return {name+'_key': os.environ.get('SIGNET_'+name.upper()+'_KEY', stored.get(name+'_key')) for name in ['deployer','receivable','incident']}


def setup(root='evidence/studio'):
    keys = credentials()
    sessions = {name:Studio(keys[name+'_key'],root) for name in ['deployer','receivable','incident']}
    owner=sessions['deployer']
    resolver=owner.deploy('deploy-signet','contracts/signet.py')
    schemas={
        'OBLIGATION':('obligation:v1',['payer_id','payee_id','consideration','period','amount_minor','currency']),
        'INCIDENT':('incident:v1',['event_date','location_id','event_kind','occurrence_id']),
        'ORGANIZATION':('organization:v1',['official_id','jurisdiction']),
    }
    for kind,(schema,fields) in schemas.items():
        owner.transaction('schema-'+kind.lower(),resolver,'register_identity_schema',[schema,fields])
        owner.transaction('policy-'+kind.lower(),resolver,'register_policy',[kind.lower(),1,schema,kind.lower()])
    receivers={}
    for kind,filename,key in [('OBLIGATION','receivable','receivable'),('INCIDENT','incident','incident'),('ORGANIZATION','receivable','receivable')]:
        receiver=sessions[key].deploy('deploy-consumer-'+kind.lower(),'contracts/'+filename+'.py',[resolver,kind.lower(),1,schemas[kind][0]])
        sessions[key].transaction('approve-'+kind.lower(),receiver,'approve_configuration')
        receivers[kind]=receiver
    corpus=json.loads(Path('evidence/public-sources.json').read_text())
    for role in ['deployer','receivable','incident']:
        owner.transaction('authority-'+role,resolver,'register_authority',[role,sessions[role].account.address,corpus['url_prefix'],corpus['authority_evidence_url']])
    state={'network':'studionet','rpc':'https://studio.genlayer.com/api','chain_id':61999,'runner':'py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6','resolver':resolver,'receivable':receivers['OBLIGATION'],'incident':receivers['INCIDENT'],'organization_policy_receiver':receivers['ORGANIZATION'],'principals':{name:s.account.address for name,s in sessions.items()},'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'contract_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in Path('contracts').glob('*.py')}}
    atomic_json(Path(root)/'deployment.json',state)
    return sessions,state,corpus


def revise_gist(corpus):
    journal=Path('evidence/studio/changed-source-edit.json')
    if journal.exists(): return
    credentials_file=json.loads(Path('.secrets/credentials.json').read_text()) if Path('.secrets/credentials.json').exists() else {}
    token=os.environ.get('GITHUB_TOKEN',credentials_file.get('github_token'))
    case=next(c for c in corpus['cases'] if c['case_id']=='changed-source')
    changed=case['records'][1]['content']+'source_revision: updated after request locking\n'
    req=urllib.request.Request('https://api.github.com/gists/'+corpus['gist_id'],method='PATCH',data=json.dumps({'files':{'changed-source-1.txt':{'content':changed}}}).encode(),headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':'application/json'})
    with urllib.request.urlopen(req) as response:
        updated=json.load(response)
    atomic_json(journal,{'gist_id':corpus['gist_id'],'synthetic':True,'changed_file':'changed-source-1.txt','new_byte_hash':hashlib.sha256(changed.encode()).hexdigest(),'revision':updated['history'][0]['version']})


def run_case(sessions,state,corpus,case,root='evidence/studio'):
    name,kind=case['case_id'],case['kind']
    owner=sessions['deployer']
    role='incident' if kind=='INCIDENT' else 'receivable'
    receiver=state['incident'] if kind=='INCIDENT' else state['receivable'] if kind=='OBLIGATION' else state['organization_policy_receiver']
    principal=sessions[role]
    manifests=[]
    for side,record in enumerate(case['records']):
        url=record['url']
        if name=='changed-source' and side:
            url='https://gist.githubusercontent.com/dotmantissa/'+corpus['gist_id']+'/raw/'+record['filename']
        raw=record['content'].encode()
        # Download public original bytes for all unmodified immutable test records.
        if name!='changed-source':
            with urllib.request.urlopen(url) as response:
                actual=response.read()
            assert actual == raw, 'Public fixture differs from local committed corpus'
        source=source_manifest(name+'-'+str(side),record['subject_id'],role,url,raw,kind.lower())
        if name=='forged-span' and side:
            source['required_spans'][0]['span_hash']='0'*64
        principal.transaction('attest-'+name+'-'+str(side),state['resolver'],'attest_source',[canonical(source)])
        manifests.append({'subject_id':record['subject_id'],'sources':[source]})
    if kind=='INCIDENT':
        consequence={'action':'LINK_INCIDENT','canonical_id':manifests[1]['subject_id'],'record_id':manifests[0]['subject_id'],'link_owner':principal.account.address.lower()}
    else:
        consequence={'action':'RESERVE_EXISTING','economic_id':manifests[1]['subject_id'],'amount_minor':12500,'reservation_owner':principal.account.address.lower()}
        principal.transaction('capacity-'+name,receiver,'register_economic_id',[manifests[1]['subject_id'],1000000])
    envelope_path=Path(root)/(name+'.request.json')
    if envelope_path.exists():
        e=json.loads(envelope_path.read_text())['envelope']
    else:
        e=request_envelope(name,owner.account.address,[principal.account.address],kind.lower(),1,manifests[0],manifests[1],receiver,consequence,1,2000000000)
        atomic_json(envelope_path,{'synthetic':True,'envelope':e,'left_manifest':manifests[0],'right_manifest':manifests[1],'consequence':consequence})
    if kind=='INCIDENT':
        principal.transaction('prepare-'+name,receiver,'propose_link',[name,canonical(e)])
    else:
        principal.transaction('prepare-'+name,receiver,'reserve',[name,canonical(e),manifests[1]['subject_id'],12500])
    owner.transaction('compare-'+name,state['resolver'],'compare_records',[name,kind.lower()+':v1',canonical(manifests[0]),canonical(manifests[1]),canonical(e)])
    if name=='changed-source': revise_gist(corpus)
    owner.transaction('evaluate-'+name,state['resolver'],'evaluate',[name])
    relation=owner.wait_relation(state['resolver'],name)
    assert relation['status']=='FINALIZED', name+' did not complete'
    assert relation['decision_vector']['relation']==case['expected'], name+' wrong relation: '+str(relation['decision_vector'])
    owner.transaction('publish-'+name,state['resolver'],'publish_to',[name,receiver,name])
    delivery=owner.wait_delivery(state['resolver'],receiver,name)
    operation=principal.read(receiver,'get_operation',[name])
    expected='QUARANTINED' if kind=='ORGANIZATION' else 'PERMITTED' if case['expected']=='SAME' else 'REFUSED_UNRESOLVED' if case['expected']=='UNKNOWN' else 'REFUSED_DISTINCT'
    assert operation['effective_status']==expected, name+' consumer did not enforce relation'
    atomic_json(Path(root)/(name+'.consumer.json'),operation)
    if kind=='INCIDENT':
        atomic_json(Path(root)/(name+'.directory.json'),principal.read(receiver,'resolve_record',[manifests[0]['subject_id']]))
    else:
        capacity=principal.read(receiver,'get_capacity',[manifests[1]['subject_id']])
        assert capacity['held_minor']==12500
        atomic_json(Path(root)/(name+'.capacity.json'),capacity)
    if case['expected']=='SAME':
        owner.transaction('alias-'+name,state['resolver'],'register_alias',[manifests[0]['subject_id'],name])
        alias=owner.read(state['resolver'],'get_alias',[manifests[0]['subject_id']])
        assert alias['active'] and alias['cluster_id']
        atomic_json(Path(root)/(name+'.alias.json'),alias)
    print(name,'CASE_VERIFIED',expected,flush=True)
    return relation,operation


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--case')
    parser.add_argument('--setup-only',action='store_true')
    args=parser.parse_args()
    sessions,state,corpus=setup()
    if args.setup_only: return
    cases=[c for c in corpus['cases'] if not args.case or c['case_id']==args.case]
    if args.case and not cases: raise ValueError('unknown case')
    for case in cases: run_case(sessions,state,corpus,case)


if __name__=='__main__': main()
