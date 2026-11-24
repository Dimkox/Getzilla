"""Unarmed first-party receiver must not accept data or invent erasure receipts."""
import importlib
import os
from pathlib import Path
import tempfile
import socket
import unittest

import httpx


@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED'), 'requires local POSIX peer credentials')
class RetrievalReceiverTests(unittest.TestCase):
    def test_real_unarmed_receiver_denies_payload_and_retirement_without_logging_source(self):
        try:
            module = importlib.import_module('getzilla_factory.retrieval_receiver')
        except ModuleNotFoundError:
            self.fail('fixed owned retrieval receiver with retirement tombstone is missing')
        with tempfile.TemporaryDirectory(prefix='getzilla-retirement-sink-') as directory:
            path = Path(directory) / 'sink.sock'
            owner = module.OwnedRetrievalReceiver(path, 'synthetic-owned-retention-credential')
            owner.start()
            try:
                transport = httpx.HTTPTransport(uds=str(path), retries=0)
                with httpx.Client(transport=transport, base_url='http://owned', trust_env=False) as client:
                    for endpoint in ('/v1/native-result-handoffs', '/v1/native-result-retirements'):
                        response = client.post(endpoint, json={'untrusted': 'PRIVATE_SENTINEL'},
                            headers={'Authorization': 'Bearer synthetic-owned-retention-credential'})
                        self.assertEqual(response.status_code, 403)
                        self.assertNotIn('PRIVATE_SENTINEL', response.text)
                self.assertIsNone(owner._payload)
            finally:
                owner.close()
            self.assertFalse(path.exists())
