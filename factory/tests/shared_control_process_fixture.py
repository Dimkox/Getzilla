"""Owned synthetic process fixture. No provider network or external attestations.

The Git pin names a real local fixture checkout. The fixed subprocess is the
provider transport only; current access, paid dispatch and PostgreSQL Factory
stop checks execute their product code without a mock or replacement permit.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def pin_source(path):
    from getzilla_factory import landing_renderer, landing_service, landing_failover_config

    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

    head, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    for module in (landing_renderer, landing_service, landing_failover_config):
        module.TARGET_BASE_SHA, module.TARGET_BASE_TREE = head, tree
    return head, tree


def provider(execution_file, model):
    from factory.tests.test_landing_normalizer import draft

    with open(execution_file, "a") as stream:
        stream.write("executed\n")
    print(
        json.dumps(
            {
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": draft().decode()}}
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46},
            }
        )
    )


def server(config_path, input_path, parent_job, login):
    import httpx
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    import uvicorn
    from getzilla_factory.api import Authenticator, create_app
    from getzilla_factory.access_authority import AccessAuthority
    from getzilla_factory.factory_stop import landing_source_id
    from getzilla_factory.landing_contracts import landing_digest
    from getzilla_factory.landing_failover_config import load_failover_config
    from getzilla_factory.landing_http import HttpLandingProfile, HttpLandingNormalizer
    from getzilla_factory.landing_intake import PrivateLandingBlobStore
    from getzilla_factory.landing_live_executors import grok_landing_executor
    from getzilla_factory.landing_renderer import ExactGitLandingWorkspace
    from getzilla_factory.landing_server import OwnedLandingRuntime
    from getzilla_factory.landing_service import LandingApplicationService
    from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
    from getzilla_factory.migrations import PostgresMigrator
    from getzilla_factory.paid_admission import PaidAccountV1, PaidTaskV1, PaidPriceV1, PaidExecutionAdmission
    from getzilla_factory.server import prepare_unix_socket
    from getzilla_factory.service import FactoryService
    from getzilla_factory.shared_landing_control import (
        SharedAuthorityControl,
        SharedLandingTask,
        install_shared_control_api,
    )
    from getzilla_factory.store import PostgresFactoryStore
    from factory.tests.postgres_fixture_reset import reset_fixture_tables
    from factory.tests.test_contracts import valid_intake

    document = json.loads(Path(config_path).read_text())
    source_path = Path(document["source_path"])
    pin_source(source_path)
    config = load_failover_config(Path(config_path))
    root = config.control_repository.parent
    url = os.environ["FACTORY_TEST_DATABASE_URL"]
    # This process runs only inside the explicitly owned disposable PG fixture.
    from factory.tests.run_disposable_exit import _binding_matches

    if not _binding_matches(
        os.environ["FACTORY_TEST_POSTGRES_CONTAINER_ID"],
        os.environ["FACTORY_TEST_POSTGRES_CONTAINER"],
        os.environ["FACTORY_TEST_POSTGRES_NONCE"],
        require_running=True,
    ):
        raise RuntimeError("bound disposable PostgreSQL required")
    PostgresMigrator(url).apply(expected_runtime_login=login)
    with psycopg.connect(url) as db, db.cursor() as cursor:
        reset_fixture_tables(cursor)
        cursor.execute("TRUNCATE factory.kill_switch_heads")
        cursor.execute("INSERT INTO factory.metric_counters(singleton) VALUES(true)")
    runtime_url = make_conninfo(**{**conninfo_to_dict(url), "user": login, "password": "synthetic-fixture-only"})
    factory = FactoryService(PostgresFactoryStore(runtime_url))
    payload = Path(input_path).read_bytes()
    backend = config.backends[1]
    request = {
        "job_id": parent_job,
        "actor_id": config.actor_id,
        "repository_id": config.repository_id,
        "exact_base_sha": config.exact_base_sha,
        "exact_base_tree": config.exact_base_tree,
        "media_type": "text/plain",
        "byte_length": len(payload),
        "content_sha256": hashlib.sha256(payload).hexdigest(),
        "config_digest": config.digest,
    }
    parent = landing_digest("landing-failover-request-v1", request)
    child = (
        "fo-"
        + landing_digest(
            "landing-failover-child-v1", {"parent": parent, "ordinal": 1, "profile": backend.profile_digest}
        )[:48]
    )
    now = datetime.now(timezone.utc)
    store = SQLiteLandingJobStore(root / "authority", repository_root=config.control_repository)
    blobs = PrivateLandingBlobStore(root / "quarantine", repository_root=config.control_repository)
    expected = blobs.accept(
        job_id=child,
        tenant_id=config.actor_id,
        repository_id=config.repository_id,
        exact_base_sha=config.exact_base_sha,
        exact_base_tree=config.exact_base_tree,
        site_id="therealaidarkfactory.online",
        media_kind="text",
        media_type="text/plain",
        chunks=(payload,),
        received_at=now,
        expires_at=now + timedelta(days=1),
    )
    source_key = {
        "tenant": "tenant-a",
        "project": "project-a",
        "provider": "local",
        "site": "site-a",
        "resource": child,
    }
    token_file = backend.token_file
    scopes = ["source:read", "landing:submit", "landing:read", "task:submit", "task:read"]
    actor_record = {
        "actor_id": config.actor_id,
        "kind": "client",
        "scopes": scopes,
        "repositories": [config.repository_id],
        "token_file": str(token_file),
        "credential_generation": 1,
        "principal_id": config.actor_id,
        "tenant_id": "tenant-a",
        "projects": [{"project_id": "project-a", "repository_id": config.repository_id}],
        "delegation_owner": None,
        "delegation_expires_at": None,
    }
    actors = {
        "schema_version": 2,
        "revision": 1,
        "actors": [actor_record],
        "groups": [],
        "sources": [
            {
                "key": source_key,
                "repository_id": config.repository_id,
                "version": "v1",
                "deleted": False,
                "readers": [config.actor_id],
                "groups": [],
                "public": False,
            }
        ],
        "destinations": [],
    }
    actors_file = root / "actors.json"
    actors_file.write_text(json.dumps(actors))
    actors_file.chmod(0o600)
    auth = Authenticator(AccessAuthority.load(actors_file))
    actor = auth.authenticate("Bearer " + token_file.read_text().strip(), "landing:submit")
    intake = valid_intake()
    intake.update(
        repository_id=expected.repository_id,
        source_type="api",
        source_id=landing_source_id(child),
        source_digest=expected.content_sha256,
        exact_base_sha=expected.exact_base_sha,
    )
    intake["m0_authority"]["observed_at"] = now.isoformat()
    with psycopg.connect(url) as db:
        db.execute(
            "INSERT INTO factory.m0_authority_observations (observation_id,observed_at,check_name,exact_head_sha,issuer,evidence_digest,repository_id,policy_digest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid.uuid4(),
                now,
                intake["m0_authority"]["check_name"],
                intake["m0_authority"]["exact_head_sha"],
                "external-trust-ci-api",
                hashlib.sha256(b"synthetic-disposable-shared-authority").hexdigest(),
                expected.repository_id,
                intake["policy_digest"],
            ),
        )
    factory.intake(intake, actor=actor, now=now)
    profile = HttpLandingProfile.for_provider("grok-vision", available=True)
    account = PaidAccountV1(
        actor.actor_id,
        "account",
        "tenant-a",
        "scheduler",
        "policy-v1",
        now.timestamp() - 1,
        now.timestamp() + 300,
        10**8,
        4,
        2,
        4,
    )
    paid = PaidTaskV1(
        "paid-child",
        config.repository_id,
        "route",
        config.exact_base_sha,
        config.exact_base_tree,
        "c" * 64,
        "synthetic-loader",
        10**8,
        1,
        10**7,
        10**6,
        ((profile.provider_id, profile.model_id, "paid-inference"),),
        expected.input_digest,
        now.timestamp() + 300,
    )
    store.install_paid_authority(account, paid, (PaidPriceV1(profile.provider_id, profile.model_id, "price-v1", 1, 1),))
    admission = PaidExecutionAdmission(store, "account", "paid-child", "synthetic-loader", "c" * 64)
    executions = root / "executions.txt"

    def transport(request):
        # Fixed command, no request-selected arguments, no provider keys/network.
        raw = subprocess.check_output(
            [
                sys.executable,
                "-m",
                "factory.tests.shared_control_process_fixture",
                "provider",
                str(executions),
                profile.model_id,
            ],
            timeout=10,
        )
        return httpx.Response(200, headers={"Content-Type": "application/json"}, stream=httpx.ByteStream(raw))

    executor = grok_landing_executor(
        profile=profile,
        credential_loader=lambda: "synthetic-not-a-provider-key",
        admission=admission,
        transport=httpx.MockTransport(transport),
    )
    (root / "scratch").mkdir(mode=0o700)
    (root / "output").mkdir(mode=0o700)
    workspace = ExactGitLandingWorkspace(source_path, scratch_root=root / "scratch")
    workspace.validate_source()
    # The fixture source has its measured Git pin and the same sealed member
    # contract as sealed_target(). Product code still builds and validates ZIPs.
    from getzilla_factory import landing_artifact_retention
    from getzilla_factory.landing_artifact import DEPLOY_MEMBERS

    landing_artifact_retention.deploy_members_for_source = lambda head, tree: DEPLOY_MEMBERS
    from getzilla_factory.landing_runtime import create_landing_artifact_builder, implemented_live_binding

    builder = create_landing_artifact_builder(
        binding=implemented_live_binding(enabled=True),
        source_repository=source_path,
        scratch_root=root / "scratch",
        output_directory=root / "output",
    )

    class ObservedLandingService(LandingApplicationService):
        def _process(self, *arguments, **keywords):
            try:
                return super()._process(*arguments, **keywords)
            except Exception:
                import traceback

                traceback.print_exc()
                raise

    service = ObservedLandingService(
        store,
        blobs,
        HttpLandingNormalizer(profile, executor, source_preflight=workspace.validate_source),
        profile_digest=profile.profile_digest,
        artifact_builder=builder,
        factory_service=factory,
    )
    owned = OwnedLandingRuntime(service, store)
    control = SharedAuthorityControl(
        owned,
        auth,
        (
            SharedLandingTask(
                actor.actor_id,
                admission,
                service,
                source_key,
                "v1",
                config.shared_task_id,
                expected,
                hashlib.sha256(b"synthetic-not-a-provider-key").hexdigest(),
            ),
        ),
    )
    app = create_app(None, auth, execution_enabled=False, landing_service=service, landing_only=True)
    install_shared_control_api(app, control)
    from starlette.responses import StreamingResponse

    @app.middleware("http")
    async def lost_response(request, call_next):
        response = await call_next(request)
        if (
            request.method == "POST"
            and request.url.path.startswith("/v1/shared-landing-control/jobs/")
            and response.status_code == 202
        ):
            (root / "headers.json").write_text(
                json.dumps(
                    [request.headers.get("X-Expected-Actor-ID"), request.headers.get("X-Expected-Profile-Digest")]
                )
            )

            async def broken():
                raise RuntimeError("synthetic dropped accepted response")
                yield b""

            return StreamingResponse(
                broken(), status_code=202, headers={"Content-Type": "application/json", "Content-Length": "1"}
            )
        return response

    listener = prepare_unix_socket(backend.socket_path)
    (root / "ready").write_text(child)
    try:
        uvicorn.Server(uvicorn.Config(app, access_log=False, log_config=None, server_header=False)).run(
            sockets=[listener]
        )
    finally:
        listener.close()
        owned.close()


def main():
    mode = sys.argv[1]
    if mode == "provider":
        provider(*sys.argv[2:])
    elif mode == "server":
        server(*sys.argv[2:])
    elif mode == "client":
        pin_source(Path(sys.argv[2]))
        from getzilla_factory.landing_failover_cli import main as cli

        raise SystemExit(cli(sys.argv[3:]))


if __name__ == "__main__":
    main()
