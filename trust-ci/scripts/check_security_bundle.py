"""Bounded local consistency feedback. No App/account/model or effectful client."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from adaptive_trust_ci import security_bundle as bundle
from adaptive_trust_ci.models import canonical_json
from adaptive_trust_ci.public_admission import read_file, validate_local_inputs


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise bundle.BundleError('invalid-arguments')


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--bundle', required=True, type=Path)
        parser.add_argument('--policy', required=True, type=Path)
        parser.add_argument('--source-root', required=True, type=Path)
        parser.add_argument('--snapshot-root', type=Path)
        parser.add_argument('--observations', type=Path)
        parser.add_argument('--input-descriptors', type=Path)
        args = parser.parse_args(argv)
        inputs = {}
        total = 0
        for name, maximum in (('bundle', bundle.BUNDLE_BYTES), ('policy', bundle.CONTROL_BYTES),
                              ('observations', bundle.CONTROL_BYTES), ('input_descriptors', bundle.CONTROL_BYTES)):
            path = getattr(args, name)
            if path is not None:
                raw = read_file(path, maximum)
                total += len(raw)
                if total > bundle.CONTROL_TOTAL:
                    raise bundle.BundleError('control-total')
                inputs[name] = raw
        evidence = bundle.parse_bundle(inputs['bundle'])
        source = evidence.source
        policy_input = bundle.bounded_json(inputs['policy'])
        bundle.fields(policy_input, ('version', 'policy_sha256'))
        if type(policy_input['version']) is not int or policy_input['version'] != 1:
            raise bundle.BundleError('unsupported-policy')
        policy = bundle.BundlePolicy(bundle.exact_digest(policy_input['policy_sha256']))
        if 'observations' in inputs:
            expected = bundle.bounded_json(inputs['observations'])
            bundle.fields(expected, ('mode', 'source_sha256'))
            if expected != {'mode': source.mode, 'source_sha256': bundle.digest(source.as_dict())}:
                raise bundle.BundleError('observation-expectation-mismatch')
        descriptors = bundle.bounded_json(inputs['input_descriptors']) if 'input_descriptors' in inputs else None
        now = datetime.now(timezone.utc)
        facts = validate_local_inputs(policy, evidence, source_root=args.source_root, snapshot_root=args.snapshot_root,
                                      descriptors=descriptors, now=now)
        observed = bundle.ObservedState(source.mode, bundle.digest(source.as_dict()))
        decision = bundle.evaluate_bundle(policy, source, evidence, observed, facts, now=now)
        output = {**asdict(decision), 'checks_executed_by_cli': [], 'independent_attestation': False}
        encoded = canonical_json(output)
        if len(encoded) > bundle.OUTPUT_BYTES:
            raise bundle.BundleError('output-size')
        print(encoded.decode())
        return 0 if decision.consistent else 1
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        print('{"consistent":false,"external_eligible":false,"provenance":"local-feedback","reasons":["input-refused"],"checks_executed_by_cli":[],"independent_attestation":false}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
