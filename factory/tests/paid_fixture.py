"""Explicit synthetic authority for protocol tests. Never a transport exemption."""

from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
from getzilla_factory.paid_admission import PaidAccountV1, PaidTaskV1, PaidPriceV1, PaidExecutionAdmission


class PaidProtocolTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        from getzilla_factory.landing_live_executors import OpenAICompatibleLandingExecutor
        from getzilla_factory.landing_provider import FixedCommandLandingProvider

        runtime = Path(
            os.environ.get("GETZILLA_TEST_RUNTIME", Path(__file__).resolve().parents[2] / ".getzilla/runtime/tests")
        )
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=runtime)
        self.addCleanup(tmp.cleanup)
        repo = Path(tmp.name) / "repo"
        repo.mkdir()
        self.paid_store = SQLiteLandingJobStore(Path(tmp.name) / "state", repository_root=repo)
        self.addCleanup(self.paid_store.close)
        now = datetime.now(timezone.utc).timestamp()
        self.paid_account = PaidAccountV1(
            "test-owner",
            "test-account",
            "test-tenant",
            "test-scheduler",
            "test-policy-v1",
            now - 1,
            now + 3600,
            10**12,
            10000,
            100,
            10000,
        )
        run = OpenAICompatibleLandingExecutor.run
        normalize = FixedCommandLandingProvider.normalize
        owner = self

        def admitted_run(executor, request):
            if executor._admission is None:
                executor._admission = owner.admission(executor.provider_id, executor.model_id, request.input_digest)
            return run(executor, request)

        def admitted_normalize(provider, request, read_blob):
            if provider._admission is None:
                provider._admission = owner.admission(
                    provider._profile.provider_id, provider._profile.model_id, request.source.input_digest
                )
            return normalize(provider, request, read_blob)

        self.addCleanup(patch.stopall)
        patch.object(OpenAICompatibleLandingExecutor, "run", admitted_run).start()
        patch.object(FixedCommandLandingProvider, "normalize", admitted_normalize).start()

    def admission(self, provider, model, input_digest):
        task = PaidTaskV1(
            uuid4().hex,
            "test-repo",
            "test-route",
            "a" * 40,
            "b" * 40,
            "c" * 64,
            "test-consumer",
            10**10,
            100,
            10**8,
            10**7,
            ((provider, model, "paid-inference"),),
            input_digest,
            self.paid_account.expires_at,
        )
        price = PaidPriceV1(provider, model, "test-price-v1", 1, 1, ("text", "docx", "image", "audio", "pdf"), 10**7)
        self.paid_store.install_paid_authority(self.paid_account, task, (price,))
        return PaidExecutionAdmission(self.paid_store, "test-account", task.task_id, "test-consumer", "c" * 64)


def configure_test_authority(store, profile):
    """Give server ownership tests a finite local grant. No live calls."""
    now = datetime.now(timezone.utc).timestamp()
    account = PaidAccountV1(
        "test-owner",
        "test-account",
        "test-tenant",
        "test-scheduler",
        "test-policy-v1",
        now - 1,
        now + 300,
        100000,
        2,
        1,
        2,
    )
    task = PaidTaskV1(
        "test-task",
        "test-repo",
        "test-route",
        "a" * 40,
        "b" * 40,
        "c" * 64,
        "test-consumer",
        100000,
        2,
        10000,
        8192,
        ((profile.provider_id, profile.model_id, "paid-inference"),),
        "a" * 64,
        account.expires_at,
    )
    store.install_paid_authority(
        account, task, (PaidPriceV1(profile.provider_id, profile.model_id, "test-price-v1", 1, 1),)
    )
    return PaidExecutionAdmission(store, account.account_id, task.task_id, task.credential_ref, task.source_identity)
