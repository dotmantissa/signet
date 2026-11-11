"""Builder CLI for signed Signet operations and crash recovery on Studio."""
import argparse
import json
import os
from pathlib import Path
from scripts.envelopes import canonical
from scripts.studio import Studio


def main():
    parser=argparse.ArgumentParser(description='Signet Studio client')
    parser.add_argument('--journal',default='.signet-journal')
    sub=parser.add_subparsers(dest='command',required=True)
    deploy=sub.add_parser('deploy')
    deploy.add_argument('contract',choices=['signet','receivable','incident'])
    deploy.add_argument('--args-file')
    deploy.add_argument('--operation-id',required=True)
    write=sub.add_parser('write')
    write.add_argument('address');write.add_argument('method');write.add_argument('--args-file');write.add_argument('--operation-id',required=True)
    view=sub.add_parser('view')
    view.add_argument('address');view.add_argument('method');view.add_argument('--args-file')
    compare=sub.add_parser('compare')
    compare.add_argument('resolver');compare.add_argument('bundle');compare.add_argument('--schema-id',required=True)
    for command in ['publish','reconcile']:
        p=sub.add_parser(command);p.add_argument('resolver');p.add_argument('consumer');p.add_argument('operation_id')
        if command=='publish':p.add_argument('request_id')
        else:p.add_argument('--attempt-id', required=True, help='Reuse to resume; change for the next bounded reconciliation attempt')
    receipt=sub.add_parser('receipt');receipt.add_argument('transaction_hash');receipt.add_argument('--operation-id',required=True)
    args=parser.parse_args()
    key=os.environ.get('SIGNET_PRIVATE_KEY')
    if not key:parser.error('Set SIGNET_PRIVATE_KEY in the environment; keys are never request arguments.')
    session=Studio(key,args.journal)
    values=json.loads(Path(args.args_file).read_text()) if getattr(args,'args_file',None) else []
    if not isinstance(values,list):parser.error('args-file must contain a JSON array')
    if args.command=='deploy':
        result=session.deploy(args.operation_id,'contracts/'+args.contract+'.py',values)
    elif args.command=='write':
        result=session.transaction(args.operation_id,args.address,args.method,values)
    elif args.command=='view':
        result=session.read(args.address,args.method,values)
    elif args.command=='compare':
        bundle=json.loads(Path(args.bundle).read_text())
        envelope=bundle['envelope']
        result=session.transaction('compare-'+envelope['request_id'],args.resolver,'compare_records',[envelope['request_id'],args.schema_id,canonical(bundle['left_manifest']),canonical(bundle['right_manifest']),canonical(envelope)])
    elif args.command=='publish':
        result=session.transaction('publish-'+args.operation_id,args.resolver,'publish_to',[args.request_id,args.consumer,args.operation_id])
    elif args.command=='reconcile':
        result=session.reconcile('reconcile-'+args.operation_id,args.resolver,args.consumer,args.operation_id,args.attempt_id)
    else:
        result=session.wait(args.transaction_hash,args.operation_id)
    print(json.dumps(result,indent=2,default=str))


if __name__=='__main__':main()
