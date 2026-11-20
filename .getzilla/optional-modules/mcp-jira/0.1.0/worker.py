"""Private capability-pipe worker. Not an MCP daemon or a second scheduler."""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import sys
import time

# Bind only this module's installed/source Core. Never borrow an ancestor Core.
HERE=Path(__file__).resolve().parent


def _bind_core():
    if HERE.name == 'mcp-jira' and HERE.parent.name == 'modules':
        stack = HERE.parent.parent
    elif HERE.parent.name == 'mcp-jira' and HERE.parent.parent.name == 'optional-modules':
        stack = HERE.parent.parent.parent
    else:
        raise RuntimeError('worker_core_layout')
    if stack.name != '.getzilla':
        raise RuntimeError('worker_core_layout')
    package = stack / 'getzilla'
    initializer = package / '__init__.py'
    archive = stack / 'getzilla.zip'
    if not initializer.is_file():
        raise RuntimeError('worker_core_missing')
    if archive.exists() and (not archive.is_file() or any(path.name != '__init__.py' for path in package.glob('*.py'))):
        raise RuntimeError('worker_core_ambiguous')
    engine = archive / 'getzilla' if archive.is_file() else package
    expected_paths = {str(package), str(engine)}
    for name, loaded in tuple(sys.modules.items()):
        if name == 'getzilla' or name.startswith('getzilla.'):
            origin = getattr(getattr(loaded, '__spec__', None), 'origin', None)
            if not isinstance(origin, str) or not Path(origin).resolve().is_relative_to(engine):
                if name != 'getzilla' or origin != str(initializer):
                    raise RuntimeError('worker_core_foreign')
    core = sys.modules.get('getzilla')
    if core is None:
        core_spec = importlib.util.spec_from_file_location('getzilla', initializer, submodule_search_locations=[str(package)])
        core = importlib.util.module_from_spec(core_spec)
        sys.modules['getzilla'] = core
        core_spec.loader.exec_module(core)
    if (getattr(core, '__file__', None) != str(initializer)
            or getattr(core, 'STACK_DIR', None) != stack
            or set(getattr(core, '__path__', ())) != expected_paths):
        raise RuntimeError('worker_core_foreign')


_bind_core()
from getzilla import execution,execution_store,state,managed_execution as managed
from getzilla import supervised_execution as supervisor
spec=importlib.util.spec_from_file_location('getzilla_mcp_worker',HERE/'__init__.py',submodule_search_locations=[str(HERE)])
package=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=package
spec.loader.exec_module(package)
from getzilla_mcp_worker.runtime import Runtime,Backend
from getzilla_mcp_worker.admission import HostBudget
from getzilla.module_runtime import ActivationRequestV1,OwnedRuntimeV1


def main():
    import ctypes
    import resource
    from dataclasses import asdict
    fd=sys.stdin.fileno()
    os.set_blocking(fd,False)
    raw=bytearray()
    end=time.monotonic()+2
    with selectors.DefaultSelector() as selector:
        selector.register(fd,selectors.EVENT_READ)
        while time.monotonic()<end:
            if not selector.select(max(0,end-time.monotonic())):
                raise ValueError('handoff_timeout')
            chunk=os.read(fd,min(4096,131073-len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw)>131072:
                raise ValueError('handoff_limit')
    value=json.loads(raw)
    root=Path(value['root']).resolve()
    state.bind_session(value['session'])
    _caller=execution.trusted_caller(root)
    identity=value['supervisor']
    if identity['host_pid']!=os.getpid() or identity['start_ticks']!=supervisor._host_identity(os.getpid()):
        raise ValueError('owner_unqualified')
    if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:
        raise ValueError('subreaper_unavailable')
    allowed=sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0,set(allowed[:2]))
    activation=ActivationRequestV1(**{**value['activation'],'operations':tuple(value['activation']['operations'])})
    class Authority:
        def validate_activation(self,request,handle):
            current=execution.trusted_caller(root)
            if (request.project,request.task_id,request.owner_id,request.authority_epoch)!=(str(root),current.logical_task_id,current.session_id,current.authority_epoch):
                raise ValueError('activation_owner_changed')
    runtime=Runtime(root,authority=Authority(),profile=value['profile'],host_budget=HostBudget(root,[root]))
    runtime.request=activation
    runtime.handle=object()
    runtime.owner=OwnedRuntimeV1(**value['owner'])
    if not runtime.current():
        raise ValueError('module_disabled')
    admission=execution.Admission(**value['admission'])
    request=execution.AdmittedRequest(**{**value['request'],'argument_bytes':value['request']['argument_bytes'].encode()})
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(request.hard_timeout_seconds+4,request.hard_timeout_seconds+4))
    resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
    record=execution._find(execution_store.load_registry(root),admission.execution_id)
    from datetime import datetime
    remaining=(datetime.fromisoformat(record['deadline']['hard_deadline_at'])-execution.SYSTEM_CLOCK.utcnow()).total_seconds()
    execution._LIVE[(str(root),admission.execution_id)]=(execution.SYSTEM_CLOCK,min(value['deadline'],time.monotonic()+max(0,remaining)),admission.execution_generation)
    class WorkerBackend(Backend):
        def started(self,root,admission,instance):
            def register(registry):
                current=execution._managed_record(root,registry,admission,instance)
                current['supervisor']=identity
                current['revision']+=1
            execution_store.mutate_registry(root,register)
            sys.stdout.buffer.write(b'R')
            sys.stdout.buffer.flush()
        def cleanup(self,process):
            return supervisor.NamespaceBackend.cleanup(self,process)
    from contextlib import ExitStack
    with ExitStack() as stack:
        selected=runtime.selected_profile(request.arguments.get('server_id'))
        tool=managed._tool(root,selected['tool_id'])
        # Source policy was checked in the authenticated host before dispatch;
        # recheck it on the current source before opening a launch gate.
        managed._policy(root,tool)
        binary=managed.Binary(root,tool.executable,tool.digest)
        stack.callback(binary.close)
        bootstrap=managed.Binary(root,str(Path(sys.executable).resolve()))
        stack.callback(bootstrap.close)
        sandbox=managed.Binary(root,'/usr/bin/bwrap')
        stack.callback(sandbox.close)
        backend=WorkerBackend(runtime,tool,binary,bootstrap,sandbox,request.label,profile=selected)
        backend.dispatch(root,admission,request)
        if backend.reply is not None:
            encoded=json.dumps(asdict(backend.reply),separators=(',',':')).encode()
            if len(encoded)<=1048575:
                sys.stdout.buffer.write(encoded)
                sys.stdout.buffer.flush()


if __name__=='__main__':
    main()
