"""Run independent Studio test cases in bounded, journaled transaction waves."""
import hashlib
import json
import subprocess
import time
from pathlib import Path
import urllib.request
from scripts.run_studio import credentials, revise_gist
from scripts.envelopes import canonical, source_manifest, request_envelope
from scripts.studio import Studio, atomic_json

ROOT = 'evidence/studio-final'
SCHEMAS = {'OBLIGATION':['payer_id','payee_id','consideration','period','amount_minor','currency'],'INCIDENT':['event_date','location_id','event_kind','occurrence_id'],'ORGANIZATION':['official_id','jurisdiction']}


def queue_wave(tasks):
    queued=[]
    for session,label,address,method,args in tasks:
        queued.append((session,label,session.queue(label,address,method,args)))
    for session in {id(s):s for s,_,_ in queued}.values():
        session.finish_batch([(label,tx) for s,label,tx in queued if s is session])


def run():
    keys=credentials()
    sessions={role:Studio(keys[role+'_key'],ROOT) for role in ['deployer','receivable','incident']}
    owner=sessions['deployer']
    resolver=owner.deploy('deploy-signet','contracts/signet.py')
    queue_wave([(owner,'schema-'+kind.lower(),resolver,'register_identity_schema',[kind.lower()+':v1',fields]) for kind,fields in SCHEMAS.items()])
    queue_wave([(owner,'policy-'+kind.lower(),resolver,'register_policy',[kind.lower(),1,kind.lower()+':v1',kind.lower()]) for kind in SCHEMAS])
    receivers={}
    # Separate account keys own the consumer contracts; all three deployments are real.
    deployments=[]
    for kind in SCHEMAS:
        role='incident' if kind=='INCIDENT' else 'receivable'
        path='contracts/incident.py' if kind=='INCIDENT' else 'contracts/receivable.py'
        label='deploy-consumer-'+kind.lower()
        tx=sessions[role].queue_deploy(label,path,[resolver,kind.lower(),1,kind.lower()+':v1'])
        deployments.append((kind,sessions[role],label,tx))
    for session in {id(s):s for _,s,_,_ in deployments}.values():
        results=session.finish_batch([(label,tx) for _,s,label,tx in deployments if s is session])
        for kind,s,label,tx in deployments:
            if s is session: receivers[kind]=results[label]['data']['contract_address']
    queue_wave([(sessions['incident' if k=='INCIDENT' else 'receivable'],'approve-'+k.lower(),receiver,'approve_configuration',[]) for k,receiver in receivers.items()])
    corpus=json.loads(Path('evidence/public-sources.json').read_text())
    queue_wave([(owner,'authority-'+role,resolver,'register_authority',[role,sessions[role].account.address,corpus['url_prefix'],corpus['authority_evidence_url']]) for role in sessions])
    state={'network':'studionet','rpc':'https://studio.genlayer.com/api','chain_id':61999,'runner':'py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6','resolver':resolver,'receivable':receivers['OBLIGATION'],'incident':receivers['INCIDENT'],'organization_policy_receiver':receivers['ORGANIZATION'],'principals':{role:s.account.address for role,s in sessions.items()},'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'contract_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('contracts').glob('*.py')}}
    atomic_json(Path(ROOT)/'deployment.json',state)
    bundles={}
    tasks=[]
    for case in corpus['cases']:
        name,kind=case['case_id'],case['kind']
        role='incident' if kind=='INCIDENT' else 'receivable'
        principal=sessions[role]
        manifests=[]
        for side,record in enumerate(case['records']):
            url=record['url']
            if name=='changed-source' and side:
                url='https://gist.githubusercontent.com/dotmantissa/'+corpus['gist_id']+'/raw/'+record['filename']
            raw=record['content'].encode()
            source=source_manifest(name+'-'+str(side),record['subject_id'],role,url,raw,kind.lower())
            if name=='forged-span' and side: source['required_spans'][0]['span_hash']='0'*64
            manifests.append({'subject_id':record['subject_id'],'sources':[source]})
            tasks.append((principal,'attest-'+name+'-'+str(side),resolver,'attest_source',[canonical(source)]))
        receiver=receivers[kind]
        if kind=='INCIDENT':
            consequence={'action':'LINK_INCIDENT','canonical_id':manifests[1]['subject_id'],'record_id':manifests[0]['subject_id'],'link_owner':principal.account.address.lower()}
        else:
            consequence={'action':'RESERVE_EXISTING','economic_id':manifests[1]['subject_id'],'amount_minor':12500,'reservation_owner':principal.account.address.lower()}
            tasks.append((principal,'capacity-'+name,receiver,'register_economic_id',[manifests[1]['subject_id'],1000000]))
        path=Path(ROOT)/(name+'.request.json')
        envelope=json.loads(path.read_text())['envelope'] if path.exists() else request_envelope(name,owner.account.address,[principal.account.address],kind.lower(),1,manifests[0],manifests[1],receiver,consequence,1,2000000000)
        bundle={'synthetic':True,'envelope':envelope,'left_manifest':manifests[0],'right_manifest':manifests[1],'consequence':consequence}
        atomic_json(path,bundle)
        bundles[name]=(case,principal,receiver,bundle)
    queue_wave(tasks)
    tasks=[]
    for name,(case,principal,receiver,bundle) in bundles.items():
        e=bundle['envelope']
        method='propose_link' if case['kind']=='INCIDENT' else 'reserve'
        args=[name,canonical(e)] if method=='propose_link' else [name,canonical(e),e['right_subject_id'],12500]
        tasks.append((principal,'prepare-'+name,receiver,method,args))
    queue_wave(tasks)
    queue_wave([(owner,'compare-'+name,resolver,'compare_records',[name,case['kind'].lower()+':v1',canonical(bundle['left_manifest']),canonical(bundle['right_manifest']),canonical(bundle['envelope'])]) for name,(case,principal,receiver,bundle) in bundles.items()])
    revise_gist(corpus)
    queue_wave([(owner,'evaluate-'+name,resolver,'evaluate',[name]) for name in bundles])
    for name,(case,principal,receiver,bundle) in bundles.items():
        relation=owner.wait_relation(resolver,name)
        assert relation['status']=='FINALIZED', name+' assessment did not finalize'
        assert relation['decision_vector']['relation']==case['expected'], name+' wrong result '+str(relation['decision_vector'])
    queue_wave([(owner,'publish-'+name,resolver,'publish_to',[name,receiver,name]) for name,(case,principal,receiver,bundle) in bundles.items()])
    for name,(case,principal,receiver,bundle) in bundles.items():
        delivery=owner.wait_delivery(resolver,receiver,name)
        operation=principal.read(receiver,'get_operation',[name])
        expected='PERMITTED' if case['expected']=='SAME' else 'REFUSED_UNRESOLVED' if case['expected']=='UNKNOWN' else 'REFUSED_DISTINCT'
        assert operation['effective_status']==expected, name+' consumer status '+operation['effective_status']
        atomic_json(Path(ROOT)/(name+'.consumer.json'),operation)
        if case['kind']=='INCIDENT':
            atomic_json(Path(ROOT)/(name+'.directory.json'),principal.read(receiver,'resolve_record',[bundle['envelope']['subject_id']]))
        else:
            capacity=principal.read(receiver,'get_capacity',[bundle['envelope']['right_subject_id']])
            assert capacity['held_minor']==12500
            atomic_json(Path(ROOT)/(name+'.capacity.json'),capacity)
        print(name,'CASE_VERIFIED',expected,flush=True)
    queue_wave([(owner,'alias-'+name,resolver,'register_alias',[bundle['envelope']['subject_id'],name]) for name,(case,principal,receiver,bundle) in bundles.items() if case['expected']=='SAME'])
    for name,(case,principal,receiver,bundle) in bundles.items():
        if case['expected']=='SAME':
            alias=owner.read(resolver,'get_alias',[bundle['envelope']['subject_id']])
            assert alias['active'] and alias['cluster_id']
            atomic_json(Path(ROOT)/(name+'.alias.json'),alias)
    atomic_json(Path(ROOT)/'suite-result.json',{'executed':True,'network':'studionet','synthetic_evidence':True,'cases':{case['case_id']:case['expected'] for case in corpus['cases']}})


if __name__=='__main__':run()
