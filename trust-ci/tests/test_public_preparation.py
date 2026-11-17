"""NEW pure live-capability controls. Kernel/IPC provenance is mocked explicitly."""
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from adaptive_trust_ci import security_bundle as bundle
ACTIVE=False

def guard(event,args):
    if ACTIVE and (event=='open' or event.startswith(('os.','socket.','subprocess.','ctypes.','shutil.'))):
        raise AssertionError('owned pure fixture denies native/network/outside I/O')
sys.addaudithook(guard)

class OwnedPreparation(unittest.TestCase):
    def test_live_capability_is_not_reconstructed_from_retained_json(self):
        path=Path(__file__).resolve().parents[1]/'src/adaptive_trust_ci/public_preparation.py'
        self.assertTrue(path.is_file(), 'live preparation contract missing')
        from adaptive_trust_ci import public_preparation as prep
        global ACTIVE
        ACTIVE=True
        try:
            source={'owned':'source'}
            report={'inventory_sha256':'1'*64}
            policy=bundle.BundlePolicy('2'*64,b'owned-unused','3'*64)
            facts=bundle.ValidationFacts(bundle.digest(source),policy.policy_digest,bundle.digest(report),'1'*64,
                (bundle.Requirement('security-inventory',True,(),'1'*64),),(),(),True,integration_digest='9'*64,integration_validated=True,content_digest='4'*64,snapshot_digest='5'*64,
                valid_until='2026-11-18T00:00:00+00:00',checker_source=('6'*40,'7'*40))
            raw=bundle.canonical_json({'facts':asdict(facts)})
            class Envelope:
                closed=True
                empty_confirmed=True
                def confirms(self,command,value):
                    return command==['fixed','--produce'] and value==raw
            with patch.object(prep,'ProducerEnvelope',Envelope):
                token=prep.from_owned(Envelope(),['fixed','--produce'],raw)
                self.assertEqual(prep.consume(token,source,report,policy,now=datetime(2026,11,17,tzinfo=timezone.utc)),facts)
                for invalid in (asdict(facts),raw,object(),None):
                    with self.assertRaises(ValueError):
                        prep.consume(invalid,source,report,policy,now=datetime(2026,11,17,tzinfo=timezone.utc))
                with self.assertRaises(ValueError):
                    prep.consume(token,source,{'inventory_sha256':'8'*64},policy,now=datetime(2026,11,17,tzinfo=timezone.utc))
                with self.assertRaises(ValueError):
                    prep.consume(token,source,report,policy,now=datetime(2026,11,19,tzinfo=timezone.utc))
                envelope=Envelope()
                envelope.empty_confirmed=False
                with self.assertRaises(ValueError):
                    prep.from_owned(envelope,['fixed','--produce'],raw)
        finally:
            ACTIVE=False

if __name__=='__main__':
    unittest.main()
