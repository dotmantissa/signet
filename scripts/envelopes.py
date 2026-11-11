"""Canonical public evidence and request builders. No secret material enters envelopes."""
import hashlib
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def source_manifest(source_id, subject_id, authority_id, url, raw, scope, revision=1):
    spans, offset = [], 0
    for line in raw.splitlines(keepends=True):
        end = offset + len(line)
        if line.strip():
            spans.append({'start': offset, 'end': end, 'span_hash': hashlib.sha256(line).hexdigest()})
        offset = end
    return {'source_id': source_id, 'subject_id': subject_id, 'authority_id': authority_id, 'channel': 'HTTPS_UTF8', 'url': url, 'raw_hash': hashlib.sha256(raw).hexdigest(), 'revision': revision, 'scope': scope, 'byte_length': len(raw), 'required_spans': spans}


def request_envelope(request_id, owner, parties, policy_id, policy_revision, left, right, consumer, consequence, generation, deadline, supersedes=''):
    return {'request_id': request_id, 'owner': owner.lower(), 'parties': sorted(set(x.lower() for x in parties)), 'policy_id': policy_id, 'policy_revision': policy_revision, 'subject_id': left['subject_id'], 'right_subject_id': right['subject_id'], 'subject_digest': digest([left['subject_id'], right['subject_id']]), 'source_manifest_digest': digest([left, right]), 'consumer': consumer.lower(), 'consequence_digest': digest(consequence), 'generation': generation, 'deadline': deadline, 'supersedes': supersedes}
