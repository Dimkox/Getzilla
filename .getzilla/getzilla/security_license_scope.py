"""Exact owned-run license applicability; raw/global coverage never becomes complete."""
from __future__ import annotations

import json
from pathlib import Path

from .security_artifacts import ArtifactError
from .security_python_target import digest,_subject,_pin_for

_SEAL=object()
_HOST={'.getzilla/config/python-test-requirements.txt','.getzilla/config/python-quality-requirements.txt'}


def _refuse():
    raise ArtifactError('license-run-scope-unavailable','selected-run scope needs the same owned pipeline/source/profile/build facts')


def _live(root,inventory,binding):
    from . import security_image_producer as producer,security_image_backend as native
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
    from . import security_image_producer as producer,security_image_backend as native
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


class Scope:
    def __init__(self,seal,root,inventory,binding,state):
        if seal is not _SEAL:
            _refuse()
        self.root,self.inventory,self.binding,self.state=Path(root),inventory,binding,state
        self.required={}
        self.host=[]
        self.inactive=[]
        for dep in inventory['dependencies']:
            if dep.get('ecosystem')=='PyPI':
                pin=_pin_for(dep,binding)
                if type(pin.get('marker_active')) is not bool:
                    _refuse()
                if not pin['marker_active']:
                    self.inactive.append(digest(_subject(dep)))
                if dep.get('usage')=='build-ci':
                    if dep['manifest'] not in _HOST:
                        self.required['unsupported-host:'+digest(_subject(dep))]={'kind':'consumer','subject':dep}
                    elif pin['marker_active']:
                        self.host.append(dep)
                        self.required['host:'+digest(_subject(dep))]={'kind':'host','subject':dep}
        for kind,rows in [('tool',inventory['tools']),('image',inventory['images'])]:
            for row in rows:
                self.required['family:'+kind+':'+digest(row)]={'kind':'family','subject':row}
        if 'factory_inputs' in binding:
            self.required['factory-output']={'kind':'output'}
        consumers=binding.get('ci_uses',{}).get('consumers',[])
        for build in inventory.get('builds',[]):
            self.required['ci-install:'+build['build_sha256']]={'kind':'consumer','recipe':build['dockerfile']}
        for dep in inventory['dependencies']:
            if dep.get('manifest')=='trust-ci/pyproject.toml' and dep.get('usage')=='build':
                for consumer in consumers:
                    self.required['build-input:'+consumer['build_sha256']+':'+digest(_subject(dep))]={'kind':'build-input','subject':dep}
        self.claim=dict(schema_version=1,kind='selected-native-security-run',source=binding['source'],run=binding['run'],
            profile_sha256=binding['profile_sha256'],inventory_sha256=inventory['digest'],
            required_ids=sorted(self.required),overall_coverage_complete=False)
        self.claim['context_sha256']=digest(self.claim)
        self.begin()

    def validate(self,inventory,binding):
        if (inventory!=self.inventory or binding!=self.binding or _live(self.root,inventory,binding) is not self.state
                or self.state.get('license_scope') is not self):
            _refuse()

    def begin(self):
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
            self.passed[key]=digest(output)
            self.details.extend(output.get('details',[]))

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
            inactive_subjects=self.inactive,unconsumed_python_subjects=[digest(_subject(dep)) for dep in self.inventory['dependencies']
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
    from . import security_image_producer as producer
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
