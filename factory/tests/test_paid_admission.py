"""Paid calls use one durable account across retries and credentials. No network."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import os
import unittest
import httpx

from getzilla_factory.landing_live_executors import qwen_landing_executor
from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
from getzilla_factory.landing_provider import LandingProviderError
from factory.tests.test_landing_live_executors import _request, _transport

SCRATCH = Path(
    os.environ.get(
        "GETZILLA_TEST_RUNTIME",
        Path(__file__).resolve().parents[1 if __name__.startswith("tests.") else 2] / ".getzilla/runtime/tests",
    )
)
SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)


class PaidAdmissionTests(unittest.TestCase):
    def setUp(self):
        from factory.tests.transport_stop_fixture import mock_transport_factory_boundary
        mock_transport_factory_boundary(self)
        from getzilla_factory.paid_admission import PaidAccountV1, PaidTaskV1, PaidPriceV1, PaidExecutionAdmission

        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.tmp.cleanup)
        repo = Path(self.tmp.name) / "repo"
        repo.mkdir()
        self.now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        self.store = SQLiteLandingJobStore(Path(self.tmp.name) / "state", repository_root=repo, clock=lambda: self.now)
        self.addCleanup(lambda: self.store.close())
        self.account = PaidAccountV1(
            "owner",
            "account",
            "tenant",
            "scheduler",
            "policy-v1",
            self.now.timestamp() - 1,
            self.now.timestamp() + 300,
            100000,
            4,
            2,
            4,
        )
        self.price = PaidPriceV1("qwen", "qwen-plus", "price-v1", 1, 1)
        self.task = PaidTaskV1(
            "task",
            "repo",
            "route",
            "a" * 40,
            "b" * 40,
            "c" * 64,
            "consumer-key",
            50000,
            2,
            100000,
            16384,
            (("qwen", "qwen-plus", "paid-inference"),),
            "a" * 64,
            self.account.expires_at,
        )
        self.store.install_paid_authority(self.account, self.task, (self.price,))
        self.admission = PaidExecutionAdmission(
            self.store, self.account.account_id, self.task.task_id, self.task.credential_ref, self.task.source_identity
        )

    def test_key_and_mock_transport_do_not_grant_authority(self):
        count = []
        executor = qwen_landing_executor(api_key="synthetic", transport=httpx.MockTransport(lambda r: count.append(r)))
        with self.assertRaisesRegex(LandingProviderError, "paid_authority_required"):
            executor.run(_request(executor))
        self.assertEqual(count, [])

    def test_duplicate_does_not_resend_and_survives_restart(self):
        executor = qwen_landing_executor(
            api_key="synthetic", transport=_transport("qwen-plus"), admission=self.admission
        )
        request = _request(executor)
        executor.run(request)
        with self.assertRaisesRegex(LandingProviderError, "paid_replay"):
            executor.run(request)
        self.store.close()
        repo = Path(self.tmp.name) / "repo"
        self.store = SQLiteLandingJobStore(Path(self.tmp.name) / "state", repository_root=repo, clock=lambda: self.now)
        from getzilla_factory.paid_admission import PaidExecutionAdmission

        renewed = PaidExecutionAdmission(self.store, "account", "task", "consumer-key", "c" * 64)
        executor = qwen_landing_executor(api_key="rotated", transport=_transport("qwen-plus"), admission=renewed)
        with self.assertRaisesRegex(LandingProviderError, "paid_replay"):
            executor.run(request)

    def test_unknown_outcome_retains_reservation_and_blocks_fallback(self):
        def fail(r):
            raise httpx.ReadTimeout("synthetic-secret")

        executor = qwen_landing_executor(
            api_key="synthetic", transport=httpx.MockTransport(fail), admission=self.admission
        )
        with self.assertRaises(LandingProviderError):
            executor.run(_request(executor))
        with self.assertRaisesRegex(LandingProviderError, "paid_unknown"):
            self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 30, 20)
        audit = self.store.paid_audit("account")
        self.assertEqual(audit[0]["state"], "unknown")
        self.assertNotIn("synthetic-secret", str(audit))

    def test_race_last_slot(self):
        other = replace(self.task, task_id="other", max_attempts=2, cost_limit_micros=100)
        self.store.install_paid_authority(self.account, other, (self.price,))

        # Two threads share the final task slot.
        def reserve(i):
            try:
                return self.store.reserve_paid(
                    "account",
                    "other",
                    "consumer-key",
                    "c" * 64,
                    "qwen",
                    "qwen-plus",
                    "paid-inference",
                    str(i) * 64,
                    50,
                    20,
                )
            except LandingProviderError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, [1, 2]))
        self.assertEqual(sum(x is not None for x in results), 1)

    def test_scope_deadline_kill_switch_and_unknown_price(self):
        for provider, model, operation in [
            ("grok", "grok-4", "paid-inference"),
            ("qwen", "qwen-plus", "paid-image"),
            ("qwen", "unknown", "paid-inference"),
        ]:
            with self.assertRaises(LandingProviderError):
                self.admission.reserve(provider, model, operation, "d" * 64, 20, 20)
        self.store.set_paid_kill_switch("account", True)
        with self.assertRaisesRegex(LandingProviderError, "paid_disabled"):
            self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 20, 20)

    def test_dry_run_and_credential_isolation(self):
        from getzilla_factory.paid_admission import PaidExecutionAdmission

        for key, dry in [("different-consumer", False), ("consumer-key", True)]:
            a = PaidExecutionAdmission(self.store, "account", "task", key, "c" * 64, dry_run=dry)
            with self.assertRaises(LandingProviderError):
                a.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 20, 20)

    def test_deadline_and_kill_switch_rechecked_at_dispatch(self):
        reservation = self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        self.store.set_paid_kill_switch("account", True)
        with self.assertRaisesRegex(LandingProviderError, "paid_disabled"):
            self.admission.dispatch(reservation, "a" * 64, "d" * 64, "qwen", "qwen-plus")
        self.store.set_paid_kill_switch("account", False)
        self.now = datetime.fromtimestamp(self.account.expires_at, timezone.utc)
        with self.assertRaisesRegex(LandingProviderError, "paid_expired"):
            self.admission.dispatch(reservation, "a" * 64, "d" * 64, "qwen", "qwen-plus")
        self.assertEqual(self.store.paid_audit("account")[0]["state"], "reserved")

    def test_fallback_and_scheduler_rotation_share_one_account(self):
        from getzilla_factory.paid_admission import PaidPriceV1, PaidExecutionAdmission

        # Primary and fallback have no fresh task allowance.
        task = replace(
            self.task,
            task_id="shared",
            cost_limit_micros=100,
            scope=(("qwen", "qwen-plus", "paid-inference"), ("grok", "grok-4", "paid-inference")),
        )
        self.store.install_paid_authority(
            self.account, task, (self.price, PaidPriceV1("grok", "grok-4", "price-v1", 1, 1))
        )
        a = PaidExecutionAdmission(self.store, "account", "shared", "consumer-key", "c" * 64)
        first = a.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        a.dispatch(first, "a" * 64, "d" * 64, "qwen", "qwen-plus")
        a.finish(first, (10, 10))
        with self.assertRaisesRegex(LandingProviderError, "paid_budget"):
            a.reserve("grok", "grok-4", "paid-inference", "e" * 64, 50, 20)
        with self.assertRaisesRegex(LandingProviderError, "paid_account_overlap"):
            self.store.install_paid_authority(
                replace(self.account, account_id="rotated", scheduler_id="other"), task, (self.price,)
            )

    def test_low_level_network_boundary_cannot_bypass_admission(self):
        import asyncio

        calls = []
        executor = qwen_landing_executor(api_key="synthetic", transport=httpx.MockTransport(lambda r: calls.append(r)))
        with self.assertRaisesRegex(LandingProviderError, "paid_authority_required"):
            asyncio.run(executor._exchange(b"{}", {}, 1))
        self.assertEqual(calls, [])

    def test_stop_revoked_by_lazy_credential_load_prevents_paid_dispatch(self):
        from unittest.mock import AsyncMock, Mock, patch
        from getzilla_factory.factory_stop import FactoryStopError
        revoked = []
        def key():
            revoked.append(True)
            return 'synthetic'
        async def check():
            if revoked:
                raise FactoryStopError('factory_stop_changed')
        capability = Mock(check=Mock(return_value=None), check_async=AsyncMock(side_effect=check))
        calls = []
        executor = qwen_landing_executor(credential_loader=key, admission=self.admission,
            transport=httpx.MockTransport(lambda request: calls.append(request)))
        with patch('getzilla_factory.factory_stop.require_stop_capability', return_value=capability), \
                patch('getzilla_factory.factory_stop.require_stop_capability_async', new=__import__('unittest.mock',fromlist=['AsyncMock']).AsyncMock(return_value=capability)):
            with self.assertRaisesRegex(LandingProviderError, 'factory_stop_changed') as error:
                executor.run(_request(executor))
        self.assertFalse(error.exception.dispatched)
        self.assertEqual(calls, [])
        self.assertEqual(self.store.paid_audit('account')[0]['state'], 'reserved')

    def test_stop_after_post_keeps_paid_exposure_unknown(self):
        import asyncio
        from unittest.mock import AsyncMock, Mock, patch
        from getzilla_factory.factory_stop import FactoryStopError
        admitted = []
        async def check():
            if admitted:
                raise FactoryStopError('factory_stop_changed')
        capability = Mock(check=Mock(return_value=None), check_async=AsyncMock(side_effect=check))
        class WaitingBody(httpx.AsyncByteStream):
            async def __aiter__(inner):
                await asyncio.sleep(2)
                yield b'{}'
        def post(request):
            admitted.append(request)
            return httpx.Response(200, headers={'Content-Type': 'application/json'}, stream=WaitingBody())
        executor = qwen_landing_executor(api_key='synthetic', admission=self.admission,
            transport=httpx.MockTransport(post))
        with patch('getzilla_factory.factory_stop.require_stop_capability', return_value=capability), \
                patch('getzilla_factory.factory_stop.require_stop_capability_async', new=__import__('unittest.mock',fromlist=['AsyncMock']).AsyncMock(return_value=capability)):
            with self.assertRaisesRegex(LandingProviderError, 'factory_stop_changed') as error:
                executor.run(_request(executor))
        self.assertTrue(error.exception.dispatched)
        self.assertEqual(len(admitted), 1)
        self.assertEqual(self.store.paid_audit('account')[0]['state'], 'unknown')

    def test_invalid_usage_blocks_account_and_retains_full_ceiling(self):
        r = self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        self.admission.dispatch(r, "a" * 64, "d" * 64, "qwen", "qwen-plus")
        with self.assertRaisesRegex(LandingProviderError, "paid_usage_invalid"):
            self.admission.finish(r, (500, 500))
        self.assertEqual(self.store.paid_audit("account")[0]["state"], "unknown")
        self.assertEqual(self.store.paid_audit("account")[0]["cost_ceiling_micros"], 70)
        with self.assertRaisesRegex(LandingProviderError, "paid_disabled"):
            self.admission.reserve("qwen", "qwen-plus", "paid-inference", "e" * 64, 50, 20)

    def test_versioned_upgrade_rolls_back_on_fault_then_recovers(self):
        import sqlite3
        from unittest.mock import patch
        from getzilla_factory import landing_sqlite_store as module

        self.store.close()
        path = Path(self.tmp.name) / "state/landing.sqlite3"
        with sqlite3.connect(path) as db:
            for table in ("shared_control_bindings", "shared_control_clock", "paid_reservations", "paid_prices", "paid_tasks", "paid_accounts"):
                db.execute("DROP TABLE " + table)
            db.execute("PRAGMA user_version=2")
        with patch.object(module, "PAID_SCHEMA", module.PAID_SCHEMA + ";INVALID SQL;"):
            with self.assertRaisesRegex(Exception, "store_schema"):
                SQLiteLandingJobStore(path.parent, repository_root=Path(self.tmp.name) / "repo")
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNone(db.execute("SELECT name FROM sqlite_schema WHERE name='paid_accounts'").fetchone())
        self.store = SQLiteLandingJobStore(
            path.parent, repository_root=Path(self.tmp.name) / "repo", clock=lambda: self.now
        )
        self.store.install_paid_authority(self.account, self.task, (self.price,))
        self.assertEqual(self.store.paid_audit("account"), [])

    def test_authority_and_prices_cannot_be_reissued_to_reset_limits(self):
        r = self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        self.store.install_paid_authority(self.account, self.task, (self.price,))
        with self.assertRaisesRegex(LandingProviderError, "paid_authority_conflict"):
            self.store.install_paid_authority(self.account, replace(self.task, cost_limit_micros=50001), (self.price,))
        with self.assertRaisesRegex(LandingProviderError, "paid_price_conflict"):
            self.store.install_paid_authority(self.account, self.task, (replace(self.price, input_micros_per_unit=2),))
        self.assertEqual(self.store.paid_audit("account")[0]["reservation_id"], r)

    def test_missing_price_with_valid_scope_denies(self):
        from getzilla_factory.paid_admission import PaidExecutionAdmission

        task = replace(self.task, task_id="unpriced", scope=(("qwen", "unpriced-model", "paid-inference"),))
        self.store.install_paid_authority(self.account, task, (self.price,))
        authority = PaidExecutionAdmission(self.store, "account", "unpriced", "consumer-key", "c" * 64)
        with self.assertRaisesRegex(LandingProviderError, "paid_price_unknown"):
            authority.reserve("qwen", "unpriced-model", "paid-inference", "d" * 64, 50, 20)
        self.assertEqual(self.store.paid_audit("account"), [])

    def test_race_one_shared_inflight_slot_across_tasks(self):
        from getzilla_factory.paid_admission import PaidExecutionAdmission

        account = replace(
            self.account,
            account_id="second-account",
            owner_id="second-owner",
            tenant_id="second-tenant",
            max_inflight=1,
        )
        for name in ("first-task", "second-task"):
            self.store.install_paid_authority(account, replace(self.task, task_id=name), (self.price,))

        def reserve(name):
            try:
                a = PaidExecutionAdmission(self.store, account.account_id, name, "consumer-key", "c" * 64)
                return a.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
            except LandingProviderError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, ("first-task", "second-task")))
        self.assertEqual(sum(x is not None for x in results), 1)

    def test_wrong_source_and_input_bindings_deny_dispatch(self):
        from getzilla_factory.paid_admission import PaidExecutionAdmission

        wrong = PaidExecutionAdmission(self.store, "account", "task", "consumer-key", "d" * 64)
        with self.assertRaisesRegex(LandingProviderError, "paid_scope"):
            wrong.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        r = self.admission.reserve("qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20)
        for inp, digest, provider, model in [
            ("e" * 64, "d" * 64, "qwen", "qwen-plus"),
            ("a" * 64, "e" * 64, "qwen", "qwen-plus"),
            ("a" * 64, "d" * 64, "grok", "grok-4"),
        ]:
            with self.assertRaisesRegex(LandingProviderError, "paid_scope"):
                self.admission.dispatch(r, inp, digest, provider, model)
        self.assertEqual(self.store.paid_audit("account")[0]["state"], "reserved")

    def test_version_one_upgrade_preserves_existing_job_and_has_no_paid_authority(self):
        import sqlite3
        from factory.tests.test_landing_sqlite_store import source
        from getzilla_factory.landing_service import LandingJobRecord

        existing = source(job_id="old-job")
        record = LandingJobRecord(existing, "accepted", None, None)
        self.store.create_or_replay(record, command_key="old-command", request_digest=existing.input_digest)
        self.store.close()
        path = Path(self.tmp.name) / "state/landing.sqlite3"
        with sqlite3.connect(path) as db:
            for table in ("shared_control_bindings", "shared_control_clock", "paid_reservations", "paid_prices", "paid_tasks", "paid_accounts"):
                db.execute("DROP TABLE " + table)
            db.execute("ALTER TABLE landing_jobs DROP COLUMN observation_json")
            db.execute("PRAGMA user_version=1")
        self.store = SQLiteLandingJobStore(
            path.parent, repository_root=Path(self.tmp.name) / "repo", recovery_limit=0, clock=lambda: self.now
        )
        recovered = self.store.get(existing.tenant_id, existing.repository_id, existing.job_id)
        self.assertEqual(recovered.source, existing)
        self.assertEqual(recovered.state, "accepted")
        self.assertEqual(self.store.paid_audit("account"), [])
        with self.assertRaisesRegex(LandingProviderError, "paid_authority_required"):
            self.store.reserve_paid(
                "account", "task", "consumer-key", "c" * 64, "qwen", "qwen-plus", "paid-inference", "d" * 64, 50, 20
            )
