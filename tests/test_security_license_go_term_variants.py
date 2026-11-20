from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_license_texts as texts,security_licenses as licenses,security_go_tool_inputs as go

class CompleteTermVariantTests(unittest.TestCase):
 def fixture(self):return json.loads((ROOT/'tests/fixtures/security-license-go-reviewed-terms.json').read_text())
 def test_complete_original_files_recognized_without_trimming(self):
  for sha,row in self.fixture()['files'].items():
   body=row['text']
   self.assertEqual(hashlib.sha256(body.encode()).hexdigest(),sha)
   identified=texts.recognized_license(body)
   ids=(identified,) if identified else texts.recognized_license_bundle(body)
   self.assertEqual(ids,tuple(row['identifiers']),sha)
   self.assertIsNone(texts.recognized_license_bundle(body+' additional condition'))
   self.assertIsNone(texts.recognized_license(body+' additional condition'))
 def test_complete_or_grant_preserves_choice_and_all_original_terms(self):
  row=next(r for r in self.fixture()['files'].values() if ' OR ' in r['expression'])
  component,files=go.component_from_terms('go-module:github.com/spdx/tools-golang@v0.5.7',{'LICENSE.code':row['text'].encode()})
  self.assertEqual(component['expression'],'Apache-2.0 OR GPL-2.0-or-later')
  chosen,ids=licenses._select_expression(component['expression'],list(licenses.ALLOWED))
  self.assertEqual(chosen,['Apache-2.0'])
  retained,_=licenses._license_evidence(files,component,ids,chosen)
  self.assertEqual(set(retained[0]['recognized_licenses']),{'Apache-2.0','GPL-2.0-or-later'})
  with self.assertRaises(ValueError):
      go.component_from_terms('unbound',{'LICENSE.code':row['text'].encode()},expression='Apache-2.0')
 def test_unknown_corpus_and_extra_views_are_not_silently_cleared(self):
  self.assertEqual(len(licenses.ALLOWED),6)
  for row in self.fixture()['deferred'].values():
   self.assertIsNone(texts.recognized_license(row['text']))
   self.assertIsNone(texts.recognized_license_bundle(row['text']))
  for row in self.fixture()['files'].values():
   if row.get('autoallow') is False or row['expression']=='BSD-2-Clause-Views':
    with self.assertRaises(ValueError):
        licenses._select_expression(row['expression'],list(licenses.ALLOWED))

 def test_complete_root_does_not_drop_unknown_corpus_or_nonlegal_files(self):
  row=next(r for r in self.fixture()['files'].values() if r['expression']=='MIT')
  for path,body in [('testdata/license.json',b'{"license":"fixture"}'),('corpus/AdColony.txt',b'noncommercial specimen; full applicable source scope unknown'),('authors/person.png',b'\x89PNG\r\n')]:
   with self.subTest(path=path),self.assertRaises(ValueError):
    go.component_from_terms('go-module:owned@v1.0.0',{'LICENSE':row['text'].encode(),path:body})

 def test_partitioned_and_bundle_requires_both_retained_grants(self):
  row=next(r for r in self.fixture()['files'].values() if ' AND ' in r['expression'])
  component,files=go.component_from_terms('go-module:partitioned@v1.0.0',{'LICENSE':row['text'].encode()})
  chosen,ids=licenses._select_expression(component['expression'],list(licenses.ALLOWED))
  self.assertEqual(set(chosen),{'Apache-2.0','BSD-3-Clause'})
  retained,_=licenses._license_evidence(files,component,ids,chosen)
  self.assertEqual(retained[0]['sha256'],hashlib.sha256(row['text'].encode()).hexdigest())
  with self.assertRaises(ValueError):
   go.component_from_terms('go-module:partitioned@v1.0.0',{'LICENSE':row['text'].encode()},expression='Apache-2.0')
