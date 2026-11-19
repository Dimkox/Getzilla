"""Exact owned-run license applicability; raw/global coverage never becomes complete."""
from __future__ import annotations

import json
import ast
import hashlib
from pathlib import Path
import re
import subprocess

from .security_artifacts import ArtifactError
from .security_python_target import digest,_subject,_pin_for

_SEAL=object()
_HOST={'.getzilla/config/python-test-requirements.txt','.getzilla/config/python-quality-requirements.txt'}
_TOOL_SOURCES=(('trivy','.getzilla/getzilla/security_acquisition.py','TRIVY_VERSION','TRIVY_ARCHIVE_SHA256'),
    ('buildkit','.getzilla/getzilla/security_image_provision.py','VERSION','ARCHIVE_SHA256'))
_TCB_ASSUMPTIONS=['Host OS, kernel, interpreter and CI-provider runtime are the external verification TCB; '
    'their artifact licenses and the entire GitHub provider are outside this selected artifact claim.']


def checker_tools(checker,*,revision=None):
    """Read two fixed checker pins as bounded literals, never execute another revision."""
    from .security_artifacts import read_file
    output={}
    for role,path,version_name,sha_name in _TOOL_SOURCES:
        if revision is None:
            raw=read_file(checker,path,65536)
        else:
            if not re.fullmatch('[0-9a-f]{40}',revision):
                _refuse()
            reference=revision+':'+path
            size=int(subprocess.run(['git','cat-file','-s',reference],cwd=checker,capture_output=True,check=True,timeout=15).stdout)
            if not 0<size<=65536:
                _refuse()
            raw=subprocess.run(['git','show',reference],cwd=checker,capture_output=True,check=True,timeout=15).stdout
            if len(raw)!=size:
                _refuse()
        values={}
        try:
            nodes=ast.parse(raw).body
        except (SyntaxError,ValueError,TypeError):
            _refuse()
        for node in nodes:
            if isinstance(node,ast.Assign):
                for name in node.targets:
                    if isinstance(name,ast.Name) and name.id in {version_name,sha_name}:
                        if name.id in values or not isinstance(node.value,ast.Constant) or type(node.value.value) is not str:
                            _refuse()
                        values[name.id]=node.value.value
        version,sha=values.get(version_name),values.get(sha_name)
        if (type(version) is not str or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}',version)
                or type(sha) is not str or not re.fullmatch('[0-9a-f]{64}',sha)):
            _refuse()
        output['checker-tool:'+role+':'+sha]=dict(kind='checker-tool',role=role,version=version,
            archive_sha256=sha,source_path=path,source_sha256=hashlib.sha256(raw).hexdigest())
    return output


def _refuse():
    raise ArtifactError('license-run-scope-unavailable','selected-run scope needs the same owned pipeline/source/profile/build facts')


def _live(root,inventory,binding):
    from . import security_image_authority as producer, security_image_authority as native
    state=producer._LIVE
    if state is None or state.get('license_entry') is not producer._LICENSE_ENTRY:
        return None
    if (native._GUARD is None or state.get('native_guard') is not native._GUARD
            or Path(state.get('root','')).absolute()!=Path(root).absolute()
            or state.get('declared_inventory')!=inventory or state.get('license_binding')!=binding
            or state.get('source')!=binding.get('source') or state.get('run')!=binding.get('run')
            or state.get('license_profile',{}).get('profile_sha256')!=binding.get('profile_sha256')):
        _refuse()
    return state


def activate(root,profile,*,_entry=None):
    """Called only by the fixed native pipeline after its actual declaration."""
    from . import security_image_authority as producer, security_image_authority as native
    from .security_python_target import binding,source_pins
    state=producer._LIVE
    if (_entry is not producer._LICENSE_ENTRY or state is None
            or native._GUARD is None or state.get('native_guard') is not native._GUARD
            or Path(state.get('root','')).absolute()!=Path(root).absolute()):
        _refuse()
    inventory=state['declared_inventory']
    observed=binding(profile)
    if (observed is None or profile['source']!=state['source'] or profile['run']!=state['run']
            or inventory['digest']!=profile['inventory_sha256']
            or digest({k:v for k,v in profile.items() if k!='profile_sha256'})!=profile['profile_sha256']
            or source_pins(root,inventory,observed['target'])!=observed.get('source_pins')):
        _refuse()
    state['license_binding']=json.loads(json.dumps(observed))
    state['license_entry']=_entry
    state['license_profile']=json.loads(json.dumps(profile))
    state['license_scope']=None
    state['license_results']={}
    from .security_tools import TRUSTED_ROOT
    state['license_checker_declarations']=checker_tools(TRUSTED_ROOT)
    state.pop('license_checker_tools',None)
    return dict(schema_version=1,profile=json.loads(json.dumps(profile)),inventory=json.loads(json.dumps(inventory)))


def current(root,inventory,binding):
    if binding is None:
        return None
    state=_live(root,inventory,binding)
    if state is None:
        return None
    scope=state.get('license_scope')
    if scope is None:
        scope=Scope(_SEAL,root,inventory,binding,state)
        state['license_scope']=scope
    scope.validate(inventory,binding)
    return scope


def requirements(inventory,binding,*,checker_tool_conditions=None):
    """Pure applicability from reobserved declarations; this grants no evidence."""
    required,host,inactive=dict(checker_tool_conditions or {}),[],[]
    for dep in inventory['dependencies']:
        if dep.get('ecosystem')=='PyPI':
            pin=_pin_for(dep,binding)
            if type(pin.get('marker_active')) is not bool:
                _refuse()
            if not pin['marker_active']:
                inactive.append(digest(_subject(dep)))
            if dep.get('usage')=='build-ci':
                if dep['manifest'] not in _HOST:
                    required['unsupported-host:'+digest(_subject(dep))]={'kind':'consumer','subject':dep}
                elif pin['marker_active']:
                    host.append(dep)
                    required['host:'+digest(_subject(dep))]={'kind':'host','subject':dep}
    for kind,rows in [('tool',inventory['tools']),('image',inventory['images'])]:
        for row in rows:
            required['family:'+kind+':'+digest(row)]={'kind':'family','subject':row}
    if 'factory_inputs' in binding:
        required['factory-output']={'kind':'output'}
    for build in inventory.get('builds',[]):
        required['ci-install:'+build['build_sha256']]={'kind':'consumer','recipe':build['dockerfile']}
        if build['dockerfile'] in {'trust-ci/Dockerfile.api','trust-ci/Dockerfile.worker','trust-ci/Dockerfile.test','trust-ci/runner.Dockerfile'}:
            for dep in inventory['dependencies']:
                if dep.get('manifest')=='trust-ci/pyproject.toml' and dep.get('usage')=='build':
                    required['build-input:'+build['build_sha256']+':'+digest(_subject(dep))]={'kind':'build-input','subject':dep}
    return required,host,inactive


class Scope:
    def __init__(self,seal,root,inventory,binding,state):
        if seal is not _SEAL:
            _refuse()
        self.root,self.inventory,self.binding,self.state=Path(root),inventory,binding,state
        self.required,self.host,self.inactive=requirements(inventory,binding,
            checker_tool_conditions=state['license_checker_declarations'])
        self.claim=dict(schema_version=1,kind='selected-native-security-run',source=binding['source'],run=binding['run'],
            profile_sha256=binding['profile_sha256'],inventory_sha256=inventory['digest'],
            required_ids=sorted(self.required),overall_coverage_complete=False,tcb_assumptions=list(_TCB_ASSUMPTIONS))
        self.claim['context_sha256']=digest(self.claim)
        self.begin()

    def validate(self,inventory,binding):
        if (inventory!=self.inventory or binding!=self.binding or _live(self.root,inventory,binding) is not self.state
                or self.state.get('license_scope') is not self):
            _refuse()

    def begin(self):
        self.state['license_results']={}
        self.passed={}
        self.gaps=[]
        self.details=[]

    def acquisition_dependencies(self):
        self.validate(self.inventory,self.binding)
        return list(self.host)

    def dependency_required(self,dep):
        return 'host:'+digest(_subject(dep)) in self.required

    def family_required(self,subject,kind):
        return 'family:'+('image' if kind=='image' else 'tool')+':'+digest(subject) in self.required

    def family_distribution(self,subject,kind):
        if not self.family_required(subject,kind):
            _refuse()
        if kind=='image' and subject.get('reference') not in self.state.get('images',{}):
            _refuse()
        return 'internal'

    def passed_condition(self,key,detail):
        if key not in self.required:
            _refuse()
        self.passed[key]=digest(detail)
        self.details.append(detail)

    def package_passed(self,dep,detail):
        if self.dependency_required(dep):
            self.passed_condition('host:'+digest(_subject(dep)),detail)

    def family_passed(self,subject,kind,detail):
        self.passed_condition('family:'+('image' if kind=='image' else 'tool')+':'+digest(subject),detail)

    def auxiliary(self,key,output):
        if key not in self.required:
            _refuse()
        self.gaps.extend(output.get('gaps',[]))
        if output.get('status')=='pass':
            if self.required[key]['kind']=='checker-tool':
                self._checker_output(output)
            self.passed[key]=digest(output)
            self.details.extend(row for row in output.get('details',[]) if row not in self.details)

    def build_inputs(self,binding,output):
        """Credit only each exact backend in its sealed actual CI installation."""
        self.validate(self.inventory,self.binding)
        from .security_ci_inputs import scope, validated_evaluation
        consumer=validated_evaluation(binding,output)
        if binding['source']!=self.binding['source'] or binding['run']!=self.binding['run']:
            _refuse()
        inventory,_=scope(binding,binding['ci_consumer'])
        installed=consumer['install_requirements']
        backend='trust-ci/requirements-build.txt'
        if backend not in installed:
            _refuse()
        prefix='build-input:'+consumer['build_sha256']+':'
        for key,condition in self.required.items():
            if not key.startswith(prefix):
                continue
            subject=condition['subject']
            matches=[dep for dep in inventory['dependencies'] if _subject(dep)==_subject(subject)]
            if len(matches)!=1:
                _refuse()
            dep=matches[0]
            pin=binding['source_pins'][digest(_subject(subject))]
            required=[item for item in inventory['dependencies'] if item['manifest']==backend
                and item['name']==dep['name'] and item['version']==dep['version']]
            if len(required)!=1:
                _refuse()
            required_pin=binding['source_pins'][digest(_subject(required[0]))]
            if required_pin['manifest_sha256']!=installed[backend] or not set(pin['hashes']) & set(required_pin['hashes']):
                _refuse()
            details=[row for row in output['details'] if row.get('ecosystem')==dep['ecosystem']
                and row.get('package')==dep['name'] and row.get('version')==dep['version']
                and row.get('manifest')==dep['manifest'] and row.get('context',{}).get('usage')==dep['usage']]
            if len(details)!=1:
                _refuse()
            detail=details[0]
            delivery=detail.get('delivery',{})
            members=delivery.get('members',{})
            if (detail.get('status')!='pass' or detail.get('distribution')!='internal'
                    or detail.get('artifact_sha256') not in set(pin['hashes']) & set(required_pin['hashes'])
                    or delivery.get('image')!=consumer['image'] or not members or not detail.get('license_files')
                    or not any(path.endswith('.dist-info/WHEEL') for path in members)
                    or any(not any(path.endswith('/'+term['path']) for path in members)
                           for term in detail.get('license_files',[])+detail.get('notice_files',[]))):
                _refuse()
            self.passed_condition(key,detail)

    def _checker_output(self,output):
        self.validate(self.inventory,self.binding)
        from .security_artifacts import artifact_identity
        expected={key:value for key,value in self.required.items() if value['kind']=='checker-tool'}
        bindings=self.state.get('license_checker_tools')
        if (type(bindings) is not dict or set(bindings)!=set(expected) or output.get('gaps')
                or type(output.get('details')) is not list or any(type(row) is not dict for row in output['details'])):
            _refuse()
        mapped=[]
        for key,source in expected.items():
            row=bindings[key]
            if (type(row) is not dict or set(row)!={'source_pins','family_artifact_id'}
                    or row['source_pins']!=source or type(row['family_artifact_id']) is not str
                    or not re.fullmatch('[0-9a-f]{64}',row['family_artifact_id'])):
                _refuse()
            mapped.append(row['family_artifact_id'])
        actual=[artifact_identity(row['family_record']) for row in output.get('details',[])
            if row.get('kind')=='tool' and type(row.get('family_record')) is dict]
        if len(set(mapped))!=len(expected) or len(actual)!=len(expected) or set(actual)!=set(mapped):
            _refuse()

    def finish(self,report):
        self.validate(self.inventory,self.binding)
        gaps=list(self.gaps)
        for key in sorted(set(self.required)-self.passed.keys()):
            kind=self.required[key]['kind']
            gaps.append({'code':'required-'+kind+'-unverified','context':key,
                'message':'actual selected-run consumption lacks qualified complete evidence'})
        selected={**self.claim,'status':'fail-for-selected-run' if gaps else 'pass-for-selected-run',
            'summary':f'{len(self.passed)}/{len(self.required)} required selected-run contexts verified; overall coverage incomplete',
            'details':self.details,'gaps':gaps,'conditions':[dict(id=key,**self.required[key],status='pass' if key in self.passed else 'unverified',
                evidence_sha256=self.passed.get(key)) for key in sorted(self.required)]}
        selected['checked_at_utc']=report.get('source_evidence',{}).get('checked_at_utc')
        selected['raw_diagnostics_sha256']=digest(report['gaps'])
        raw_coverage=dict(status=report['status'],complete=False,raw_declarations=len(self.inventory['dependencies']),
            inactive_subjects=self.inactive,outside_host_subjects=[digest(_subject(dep)) for dep in self.inventory['dependencies']
                if dep.get('ecosystem')=='PyPI' and not self.dependency_required(dep)])
        selected['raw_coverage_sha256']=digest(raw_coverage)
        records=self.state.setdefault('license_results',{})
        if len(records)>=16:
            records.clear()
        records[digest(selected)]=(_SEAL,self)
        report['selected_run']=selected
        report['raw_coverage']=raw_coverage
        report['status']='overall-incomplete'
        report['overall_coverage_complete']=False
        return report


def validate_result(value,*,profile=None,inventory_sha256=None,now=None,diagnostics=None,raw_coverage=None):
    from . import security_image_authority as producer
    try:
        state=producer._LIVE
        record=state.get('license_results',{}).get(digest(value)) if state is not None else None
        if type(record) is not tuple or len(record)!=2 or record[0] is not _SEAL:
            return False
        scope=record[1]
        scope.validate(scope.inventory,scope.binding)
        if (value.get('overall_coverage_complete') is not False or value.get('context_sha256')!=scope.claim['context_sha256']
                or inventory_sha256 is not None and value['inventory_sha256']!=inventory_sha256
                or profile is not None and value['profile_sha256']!=profile.get('profile_sha256')):
            return False
        if now is not None and value.get('status')=='pass-for-selected-run':
            from .security_data import _timestamp,MAX_AGE_SECONDS
            if not 0<=(now-_timestamp(value['checked_at_utc'])).total_seconds()<=MAX_AGE_SECONDS:
                return False
        if diagnostics is not None and digest(diagnostics)!=value.get('raw_diagnostics_sha256'):
            return False
        if raw_coverage is not None and (raw_coverage.get('complete') is not False
                or digest(raw_coverage)!=value.get('raw_coverage_sha256')):
            return False
        return True
    except (ArtifactError,ValueError,TypeError,KeyError):
        return False


def declaration_expectation(root,checker,inputs,source,run,*,now,scratch,checker_revision=None):
    """Reobserve source applicability outside the native job; never restore its seals."""
    from .public_security_context import _profile_declaration,validate_selection_authority
    from .expanded_security import _policy_digest
    from .security_inventory import declared_inventory
    from .security_python_target import validate_target,source_pins,closure_graphs
    from .security_licenses import load_policy
    from .security_factory_inputs import declaration
    from .security_data import _timestamp,MAX_AGE_SECONDS
    from .security_oci import LIMITS,validate_selection
    if (type(inputs) is not dict or set(inputs)!={'schema_version','profile','inventory','selection','catalog'}
            or type(inputs['schema_version']) is not int or inputs['schema_version']!=1):
        _refuse()
    profile=inputs['profile']
    selection=inputs['selection']
    validate_selection_authority(source,run,selection,now=now)
    inventory=declared_inventory(root,selection)
    if inventory!=inputs['inventory']:
        _refuse()
    target=validate_target(profile['python_target'])
    pins=source_pins(root,inventory,target)
    graphs=closure_graphs(root,inventory)
    factory=declaration(root,inventory,load_policy(checker),scratch=scratch)
    uses=profile.get('python_ci_uses')
    if inventory.get('builds'):
        if (type(uses) is not dict or uses.get('source')!=source or uses.get('run')!=run
                or uses.get('inventory_sha256')!=inventory['digest'] or uses.get('closure_graphs_sha256')!=digest(graphs)):
            _refuse()
        from .security_python_target import CI_INSTALL_RECIPES, ci_install_context
        mapping={recipe:value[0] for recipe,value in CI_INSTALL_RECIPES.items()}
        expected={row['build_sha256']:row for row in inventory['builds'] if row['dockerfile'] in mapping}
        consumers=uses.get('consumers')
        if (type(consumers) is not list or len(consumers)!=len(expected)
                or {row.get('build_sha256') for row in consumers}!=set(expected)):
            _refuse()
        for consumer in consumers:
            build=expected[consumer['build_sha256']]
            requirements_path=mapping[build['dockerfile']]
            context=ci_install_context(root,build['dockerfile'])
            if context is None:
                _refuse()
            images=[row for row in inventory['images'] if row['manifest']==build['manifest'] and row['line']==build['line']]
            if (consumer.get('recipe')!=build['dockerfile'] or consumer.get('recipe_sha256')!=build['recipe_sha256']
                    or consumer.get('requirements')!=requirements_path
                    or consumer.get('requirements_sha256')!=graphs['evidence'].get(requirements_path)
                    or consumer.get('install_requirements')!=context['install_requirements']
                    or any(graphs['evidence'].get(path)!=sha for path,sha in context['install_requirements'].items())
                    or len(images)!=1 or consumer.get('image')!=images[0]['reference']
                    or consumer.get('distribution')!='internal' or consumer.get('purpose')!='isolated-public-ci'):
                _refuse()
            if consumer.get('image_target_observed') is True:
                observed=validate_target(consumer['target'])
                if consumer.get('source_pins')!=source_pins(root,inventory,observed):
                    _refuse()
    elif uses is not None:
        _refuse()
    limits={key:profile['image_profile'][key] for key in LIMITS} if inventory['images'] else None
    created=_timestamp(profile['created_at'])
    if not 0<=(now-created).total_seconds()<=MAX_AGE_SECONDS:
        _refuse()
    normalized=_profile_declaration(source,inventory,profile['roots'],run,_policy_digest(checker),now=created,
        image_artifacts=inputs['catalog'],image_selection=selection,package_target=target,package_pins=pins,
        factory_inputs=factory,package_graphs=graphs,package_ci_uses=uses,
        public_execution=profile.get('public_execution_sha256'),image_limits=limits)
    if profile!=normalized:
        _refuse()
    if inventory['images']:
        # Declaration geometry only. This neither imports OCI bytes nor restores
        # the measured native authority needed to consume the larger profile.
        validate_selection(inputs['catalog'],inventory,{**profile['image_profile'],**LIMITS})
    binding=dict(target=target,source=source,run=run,inventory_sha256=inventory['digest'],
        profile_sha256=profile['profile_sha256'],source_pins=pins,closure_graphs=graphs)
    if factory is not None:
        binding['factory_inputs']=factory
    required,_,_=requirements(inventory,binding,checker_tool_conditions=checker_tools(checker,revision=checker_revision))
    claim=dict(schema_version=1,kind='selected-native-security-run',source=source,run=run,
        profile_sha256=profile['profile_sha256'],inventory_sha256=inventory['digest'],
        required_ids=sorted(required),overall_coverage_complete=False,tcb_assumptions=list(_TCB_ASSUMPTIONS))
    claim['context_sha256']=digest(claim)
    return dict(claim=claim,conditions=required)
