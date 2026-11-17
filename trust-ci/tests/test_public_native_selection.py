"""NEW native consumption data controls; inventory/source I/O are mocked seams."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'.getzilla'))
from getzilla import expanded_security as expanded
from getzilla import security_cli as cli
ACTIVE=False


def guard(event,args):
    if ACTIVE and (event=='open' or event.startswith(('os.','socket.','subprocess.','ctypes.','shutil.'))):
        raise AssertionError('owned data fixture denies all native/network/outside I/O')
sys.addaudithook(guard)


class NativeSelectionCurrentness(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,11,17,tzinfo=timezone.utc)
        self.source=dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
                         candidate_clean=True,checker_clean=True,same_project=True)
        self.run=dict(provider='github-actions',repository='owned/fixture',run_id='1',run_attempt='2',head_sha='a'*40)
        self.selection=dict(schema_version=1,source=self.source,run=self.run,created_at=self.now.isoformat(),uses=[{}])
        self.inventory=dict(complete=True,gaps=[],digest='e'*64,images=[],dependencies=[],tools=[])
        self.roots=dict(database='/UNREAD/database',artifacts='/UNREAD/artifacts',tools='/UNREAD/tools')
        self.profile=cli.input_profile(self.source,self.inventory,self.roots,self.run,'f'*64,
                                       now=self.now,image_selection=self.selection)
    def consume(self, *, now=None, run=None):
        global ACTIVE
        env=dict(GETZILLA_SECURITY_IMAGE_SELECTION='/UNREAD/selection',GETZILLA_SECURITY_DB=self.roots['database'],
                 GETZILLA_SECURITY_ARTIFACTS=self.roots['artifacts'],GETZILLA_SECURITY_TOOLS=self.roots['tools'],
                 GETZILLA_SECURITY_INPUT_PROFILE=json.dumps(self.profile))
        with patch.object(expanded,'read_image_selection',return_value=self.selection), \
                patch.object(expanded,'declared_inventory',return_value=self.inventory), \
                patch.object(expanded,'_selection_authority',return_value=(self.source,run or self.run)) as authority, \
                patch.object(expanded,'_policy_digest',return_value='f'*64):
            ACTIVE=True
            try:
                result=expanded.selected_inventory(Path('/UNREAD/source'),environ=env,now=now or self.now)
                self.assertEqual(authority.call_count,2)
                return result
            finally:
                ACTIVE=False
    def test_current_declaration_needs_both_independent_source_observations(self):
        self.assertEqual(self.consume(),self.inventory)
    def test_stale_declaration_is_refused_at_native_consumption(self):
        with self.assertRaisesRegex(cli.SecurityDataError,'future or stale'):
            self.consume(now=self.now+timedelta(days=4))
    def test_foreign_attempt_is_not_recovered_from_supplied_profile(self):
        with self.assertRaisesRegex(cli.SecurityDataError,'independently observed'):
            self.consume(run={**self.run,'run_attempt':'3'})


if __name__=='__main__':
    unittest.main()
