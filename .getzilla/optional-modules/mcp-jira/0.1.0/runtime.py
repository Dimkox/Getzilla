"""Opt-in native host port. One-shot stdio attempts use canonical execution only."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from getzilla import execution, execution_store, fsx, managed_execution as managed, state
from getzilla.component_state import BoundRoot, read_state
from getzilla.module_runtime import OwnedRuntimeV1, NativeProfileProofV1, QuiescenceProofV1
from getzilla.optional_modules import _validate_installed

# Sibling modules are loaded by the optional native host, never by Core startup.
from .transport import Session, Reply
from .admission import gate, scope_key

MODULE = 'mcp-jira'


def owner_prefix(owner):
    return hashlib.sha256((owner.owner_handle + '\0' + owner.generation).encode()).hexdigest()


class Runtime:
    """Implements the existing lifecycle ports; no new lifecycle/worker registry."""
    def __init__(self, root, *, authority, profile, host_budget):
        self.root, self.authority, self.profile = Path(root).resolve(), authority, dict(profile)
        self.host_budget = host_budget
        self.request = self.handle = self.owner = None

    def selected_profile(self, server_id=None):
        if 'servers' not in self.profile:
            if server_id is not None:
                raise execution.ExecutionError('mcp_server_scope')
            return self.profile
        servers = self.profile['servers']
        if not isinstance(servers, dict) or not 1 <= len(servers) <= 16 or server_id not in servers:
            raise execution.ExecutionError('mcp_server_scope')
        return servers[server_id]

    def prepare(self, request, generation, handle):
        # The lifecycle already checked explicit project activation. Reserve no
        # worker, connection, token lookup, registration or network here.
        self.request, self.handle = request, handle
        self.owner = OwnedRuntimeV1('mcp-' + request.digest()[:48], generation)
        return self.owner

    def inspect_owned(self, request, owner, handle):
        profiles = self.profile.get('servers', {'default': self.profile})
        if (request.native_profile != 'managed-stdio-v1' or not isinstance(profiles, dict) or not 1 <= len(profiles) <= 16
                or any(not isinstance(profile, dict) or profile.get('transport') != 'stdio'
                    or profile.get('credential_scope') != 'local-uid:' + str(os.getuid()) for profile in profiles.values())):
            raise execution.ExecutionError('mcp_profile_unsupported')
        if request.scope_digest != hashlib.sha256(json.dumps(self.profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest():
            raise execution.ExecutionError('mcp_profile_scope_changed')
        self.authority.validate_activation(request, handle)
        return NativeProfileProofV1(request.digest(), owner.generation, owner.owner_handle)

    def current(self):
        if not self._local_current():
            return False
        self.authority.validate_activation(self.request, self.handle)
        return True

    def _local_current(self):
        # Check disabled state before provider config, authority, credentials or
        # process admission. This read creates no file and loads no credential.
        with BoundRoot(self.root) as binding:
            if binding.read('.getzilla/runtime/modules/pending.json') is not None:
                return False
            record = read_state(self.root, binding=binding).manifest['components'].get('module:' + MODULE)
            if (record is None or not record['module']['enabled']
                    or record['module']['runtime']['state'] != 'enabled'):
                return False
            _validate_installed(binding, MODULE, record)
            if self.request is not None and set(record['module']['grants']) != set(self.request.operations):
                return False
            active = record['module']['runtime']
            if self.request is None or self.owner is None or (
                active['owner_handle'], active['generation'], active['request_digest']
            ) != (self.owner.owner_handle, self.owner.generation, self.request.digest()):
                return False
        if self.request.scope_digest != hashlib.sha256(json.dumps(self.profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest():
            return False
        caller = execution.trusted_caller(self.root)
        return (self.request.task_id, self.request.owner_id, self.request.authority_epoch) == (
            caller.logical_task_id, caller.session_id, caller.authority_epoch)

    def attest_tool(self, root, event):
        from getzilla.supply_chain import ManagedToolIdentity
        if Path(root).resolve() != self.root or not self.current():
            raise ValueError('mcp_disabled')
        profile = self.selected_profile((event.get('tool_input') or {}).get('server_id'))
        name = event.get('tool_name')
        prefix = 'mcp__managed_stdio__'
        if not isinstance(name, str) or not name.startswith(prefix) or profile['tools'].get(name[len(prefix):]) != 'read':
            raise ValueError('mcp_tool_unqualified')
        version = profile.get('server_version')
        if not isinstance(version, str) or not 1 <= len(version) <= 64:
            raise ValueError('mcp_version_unqualified')
        selected = managed._tool(self.root, profile['tool_id'])
        with BoundRoot(self.root) as binding:
            record = read_state(self.root, binding=binding).manifest['components']['module:' + MODULE]['module']
            dependencies = hashlib.sha256(json.dumps(dict(dependencies=record['dependencies'],
                descriptor=record['runtime']['descriptor_sha256']), sort_keys=True).encode()).hexdigest()
        return ManagedToolIdentity(record['manifest_sha256'], selected.digest,
            record['version'] + '/' + profile['protocol'] + '/' + version, dependencies,
            hashlib.sha256((str(self.root) + '\0' + profile['credential_scope']).encode()).hexdigest())

    def quiesce(self, owner, deadline):
        # Ownership is the actual opaque lifecycle owner/generation embedded in
        # the independently stored MCP request ID, not a PID or display alias.
        prefix = owner_prefix(owner)
        while time.monotonic() < deadline:
            records = execution_store.load_registry(self.root)['records']
            pending = [record for record in records.values() if (record.get('mcp_request_id') or '').startswith(prefix)
                       and (record['execution_status'] in {'running', 'cancel_requested'}
                            or record['cleanup_status'] in {'pending', 'failed', 'unconfirmed'})]
            if not pending:
                return QuiescenceProofV1(owner.owner_handle, owner.generation, 0)
            for record in pending:
                try:
                    caller = execution.trusted_caller(self.root, execution_id=record['execution_id'])
                    execution.cancel(self.root, caller, record['execution_id'], backend=managed.Backend())
                except (ValueError, OSError):
                    pass  # The owning runner also observes the durable disable.
            time.sleep(min(.02, max(0, deadline - time.monotonic())))
        return QuiescenceProofV1(owner.owner_handle, owner.generation, len(pending))

    def call(self, *, tool, arguments, intent_key, hard_timeout_seconds=30, server_id=None):
        if not self.current():
            return {'status': 'disabled', 'workers_started': 0, 'network_calls': 0}
        from getzilla.supply_chain import check_tool_trust
        if not check_tool_trust(self.root, {'tool_name': 'mcp__managed_stdio__' + tool, 'tool_input': {'server_id': server_id}}, managed_adapter=self)[0]:
            raise execution.ExecutionError('mcp_identity_unverified')
        if 'jira.read' not in self.request.operations:
            raise execution.ExecutionError('mcp_read_not_granted')
        profile = self.selected_profile(server_id)
        if profile.get('credential_scope') != 'local-uid:' + str(os.getuid()):
            raise execution.ExecutionError('mcp_credential_profile_unqualified')
        if (profile.get('transport') != 'stdio' or profile.get('protocol') != '2025-11-25'
                or not isinstance(profile.get('credential_scope'), str)):
            raise execution.ExecutionError('mcp_profile_unsupported')
        operations = profile.get('tools', {})
        if operations.get(tool) != 'read':
            raise execution.ExecutionError('mcp_write_transport_unqualified')
        if type(hard_timeout_seconds) is not int or not 1 <= hard_timeout_seconds <= 300:
            raise execution.ExecutionError('mcp_invalid_budget')
        caller = execution.trusted_caller(self.root)
        selected = managed._tool(self.root, profile['tool_id'])
        managed._policy(self.root, selected)
        endpoint = 'stdio:' + hashlib.sha256(json.dumps([selected.digest, selected.arguments], separators=(',', ':')).encode()).hexdigest()
        label = scope_key(endpoint=endpoint, project=str(self.root),
            credential_scope=profile['credential_scope'], configuration={'protocol': profile['protocol']})
        request_id = owner_prefix(self.owner) + secrets.token_hex(16)
        with ExitStack() as stack:
            binary = managed.Binary(self.root, selected.executable, selected.digest)
            stack.callback(binary.close)
            bootstrap = managed.Binary(self.root, str(Path(sys.executable).resolve()))
            stack.callback(bootstrap.close)
            sandbox = managed.Binary(self.root, '/usr/bin/bwrap')
            stack.callback(sandbox.close)
            backend = SupervisorBackend(self, selected, binary, bootstrap, sandbox, label, profile=profile)
            request = execution.SubmitRequest(intent_key, {'tool': tool, 'arguments': arguments,
                'server_id': server_id, 'module_generation': self.owner.generation, 'profile_digest': hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()},
                hard_timeout_seconds, label=label, mcp_request_id=request_id)
            try:
                result = execution.submit(self.root, caller, request, backend=backend)
            except execution.ExecutionError as error:
                if error.code in {'backend_saturated', 'registry_full'}:
                    raise execution.ExecutionError('resource_busy') from error
                raise
            return {'execution': result, 'reply': backend.reply, 'result_status': 'available' if backend.reply is not None else 'not_retained', 'management': 'managed',
                    'remote_termination_confirmed': False}


class Backend(managed.Backend):
    def __init__(self, runtime, tool, binary, bootstrap, sandbox, label, *, profile=None):
        super().__init__(tool, binary, bootstrap)
        self.runtime, self.sandbox, self.label = runtime, sandbox, label
        self.profile = runtime.profile if profile is None else profile
        self.reply = None
        self.gate_read = self.gate_write = None

    def allocation_lock(self):
        return self.runtime.host_budget.allocation_lock()

    def admit_resources(self, registry, request):
        if request.label != self.label or not self.runtime._local_current():
            raise execution.ExecutionError('mcp_disabled')
        reason = gate(self.runtime.host_budget.snapshot(self.runtime.root, registry), self.label)
        if reason:
            raise execution.ExecutionError(reason)

    def spawn(self, root):
        self.gate_read, self.gate_write = os.pipe()
        # A distinct gate preserves real MCP stdin. bwrap creates a private PID
        # and network namespace; all credentials/network profiles stay outside.
        command = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-net',
            '--die-with-parent', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/run', '--ro-bind', f'/proc/self/fd/{self.binary.fd}', '/run/getzilla-executable',
            '--block-fd', str(self.gate_read), '--chdir', str(root), '/run/getzilla-executable', *self.tool.arguments]
        return fsx.owned_popen(command, executable=f'/proc/self/fd/{self.sandbox.fd}',
            pass_fds=(self.sandbox.fd, self.binary.fd, self.gate_read), cwd=root, env=managed._ENVIRONMENT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def dispatch(self, root, admission, request):
        admission.consume(root, request)
        instance = secrets.token_hex(16)
        execution._begin_managed(root, admission, instance, self.launcher_digest(), self.binary.digest)
        self.started(root, admission, instance)
        process = pidfd = session = None
        confirmed = True
        reply = None
        def watch():
            if not self.runtime.current():
                return 'disabled'
            return execution._managed_watch(root, admission, instance)
        def recheck():
            if not self.runtime.current() or managed._tool(root, self.tool.id) != self.tool:
                raise execution.ExecutionError('mcp_disabled')
            managed._policy(root, self.tool)
        def remote_task(value):
            def update(registry):
                record = execution._managed_record(root, registry, admission, instance)
                record['remote_task_id'] = value
                record['revision'] += 1
            execution_store.mutate_registry(root, update)
        try:
            recheck()
            process = self.spawn(root)
            pidfd = os.pidfd_open(process.pid)
            execution._register_managed(root, admission, instance, process.pid, managed._start_identity(process, pidfd))
            def release(guard):
                guard()
                if os.write(self.gate_write, b'R') != 1:
                    raise OSError('launch gate unavailable')
                os.close(self.gate_write); self.gate_write = None
            execution._release_managed(root, admission, instance, recheck, release)
            deadline = execution._LIVE[(str(root.resolve()), admission.execution_id)][1]
            session = Session(process, deadline=deadline, watch=watch, request_id=request.mcp_request_id,
                              on_remote_task=remote_task, expected_server_version=self.profile['server_version'])
            reply = session.call(request.arguments['tool'], request.arguments['arguments'])
        except (ValueError, OSError, execution_store.RegistryError):
            from .transport import Reply
            reply = Reply('policy', reason='native_admission_unavailable')
        finally:
            if session is not None:
                session.close()
            if process is not None:
                confirmed = self.cleanup(process)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
            for descriptor in (self.gate_read, self.gate_write, pidfd):
                if descriptor is not None:
                    os.close(descriptor)
        self.reply = reply
        healthy = reply.status in {'success', 'domain'}
        status = 'succeeded' if healthy else 'timed_out' if reply.status == 'deadline' else (
            'failed' if reply.status in {'infra', 'unsupported', 'policy'} else 'cancelled')
        reason = 'mcp_infra_' + reply.reason if reply.status == 'infra' else 'mcp_' + reply.status
        # Reply contents stay outside the registry preview. A source admission
        # policy still decides whether any Jira content can enter model context.
        execution._finish_managed(root, admission, instance, {'execution_status': status,
            'terminal_reason': reason[:80], 'cleanup_status': 'confirmed' if confirmed else 'unconfirmed',
            'operation_outcome': 'unknown' if reply.remote_task_id and not reply.remote_confirmed else 'not_applicable', 'output': {'preview': '', 'observed_bytes': 0,
                'retained_bytes': 0, 'dropped_bytes': 0, 'truncated': False, 'complete_output': True}})
        return None


class SupervisorBackend(Backend):
    """Native host custody, using the existing supervised attempt handles."""
    supervised = True
    supervised_limit = 8

    def dispatch(self, root, admission, request):
        from dataclasses import asdict
        from getzilla import supervised_execution as supervisor
        from .transport import CAP
        import selectors
        caller = execution.trusted_caller(root)
        process = fsx.owned_popen([str(Path(sys.executable).resolve()), '-I', '-S',
            str(Path(__file__).with_name('worker.py'))], executable=f'/proc/self/fd/{self.bootstrap.fd}',
            pass_fds=(self.bootstrap.fd,), cwd=root, env=supervisor._environment(caller.session_id),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        supervisor._HANDLES[admission.execution_id] = process
        identity = dict(profile=supervisor.PROFILE, host_pid=process.pid, start_ticks=supervisor._host_identity(process.pid))
        deadline = execution._LIVE[(str(root.resolve()), admission.execution_id)][1]
        envelope = dict(root=str(root), session=caller.session_id, admission=asdict(admission),
            request=dict(intent_key=request.intent_key, argument_bytes=request.argument_bytes.decode(),
                hard_timeout_seconds=request.hard_timeout_seconds,label=request.label,
                operation_id=request.operation_id,mcp_request_id=request.mcp_request_id,remote_task_id=request.remote_task_id),
            activation=asdict(self.runtime.request),owner=asdict(self.runtime.owner),profile=self.runtime.profile,
            supervisor=identity,deadline=deadline)
        raw = json.dumps(envelope,separators=(',',':')).encode()
        if len(raw)>131072:
            managed._cleanup(process)
            raise execution.ExecutionError('mcp_handoff_limit')
        os.set_blocking(process.stdin.fileno(),False)
        offset=0
        handoff_end=min(deadline,time.monotonic()+2)
        try:
            while offset<len(raw):
                if time.monotonic()>=handoff_end:
                    raise execution.ExecutionError('mcp_handoff_timeout')
                try: offset+=os.write(process.stdin.fileno(),raw[offset:offset+4096])
                except BlockingIOError: time.sleep(.002)
        finally:
            process.stdin.close()
        output=bytearray()
        end=deadline+4
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(),False)
            selector.register(process.stdout,selectors.EVENT_READ)
            while time.monotonic()<end:
                if selector.select(min(.02,max(0,end-time.monotonic()))):
                    chunk=os.read(process.stdout.fileno(),min(65536,CAP+1-len(output)))
                    if not chunk: break
                    if len(chunk)>CAP-len(output):
                        managed._cleanup(process)
                        raise execution.ExecutionError('mcp_result_limit')
                    output.extend(chunk)
                if process.poll() is not None:
                    # Drain the bounded pipe before checking its receipt.
                    continue
        process.stdout.close()
        if process.poll() is None:
            managed._cleanup(process)
        process.wait(timeout=2)
        if not output.startswith(b'R'):
            raise execution.ExecutionError('mcp_start_unconfirmed')
        if len(output)>1:
            try: self.reply=Reply(**json.loads(output[1:]))
            except (ValueError,TypeError): self.reply=None
        return None
