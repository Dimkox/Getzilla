"""Local artifact license policy evaluation, without network or package execution.

The result has artifact-integrity-only assurance. It is not a legal opinion,
publisher authentication, a human approval, or an independent CI qualification.
Unknown licenses, use scope and obligations remain explicit human-review gaps.
"""
from __future__ import annotations  # noqa: F401 compatibility module exports

import hashlib  # noqa: F401 compatibility module exports
import json  # noqa: F401 compatibility module exports
import re  # noqa: F401 compatibility module exports
import subprocess  # noqa: F401 compatibility module exports
from datetime import datetime  # noqa: F401 compatibility module exports
from pathlib import Path, PurePosixPath  # noqa: F401 compatibility module exports
from urllib.parse import urlsplit  # noqa: F401 compatibility module exports

from .security_osv_snapshot import VulnerabilityError, _pypi_key, _semver_key, normalize_name  # noqa: F401 compatibility module exports
from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, archive_files,
                                 artifact_identity, select_artifact, package_key, package_metadata, read_file, verify_origin, safe_parts)  # noqa: F401 compatibility module exports
from .security_artifacts import family_evidence, select_family  # noqa: F401 compatibility module exports
from .security_data import MAX_AGE_SECONDS, SecurityDataError, _clock, _json, _timestamp  # noqa: F401 compatibility module exports
from .security_license_texts import recognized_license, recognized_license_bundle, reviewed_ancillary  # noqa: F401 compatibility module exports
from .security_deliveries import verify_deliveries  # noqa: F401 compatibility module exports

# A qualified expression subset, not a claim to parse every SPDX vocabulary
# revision. These known alternatives may occur in OR but are never autoallowed.






























from .security_license_contracts import (  # noqa: F401 exact contract compatibility exports
    POLICY_PATH, ALLOWED, _CANONICAL, _NONALLOW, _RECOGNIZED, _policy, _repository_identity, load_policy, _distribution_for, factory_offline_intent, attach_factory_offline_intent, _select_expression, _license_evidence, _satisfies, _extra_name, _extras, _validate_extra_scope, _marker_required, _closure, _family_age, artifact_catalog_source,
)  # noqa: F401 compatibility module exports

def evaluate_artifacts(inventory: dict, artifacts: Path, policy: dict, *, now: datetime | None = None,
                       target_binding: dict | None = None, run_context=None,
                       _factory_parent_binding: dict | None = None) -> dict:
    """Evaluate exact package artifacts; expose every unsupported/missing obligation."""
    result = {'status': 'fail', 'summary': '', 'details': [], 'gaps': [], 'assurance': 'artifact-integrity-only',
              'inventory_digest': inventory.get('digest') if isinstance(inventory, dict) else None, 'policy_digest': None}
    selected_required=True
    if run_context is not None:
        from .security_license_scope import Scope
        if not isinstance(run_context,Scope):
            raise ArtifactError('license-run-scope-unavailable','caller declarations cannot select a license run scope')
        run_context.validate(inventory,target_binding)
        run_context.begin()

    def gap(code, message, dep=None, *, selected=None):
        value={'code': code, 'message': message, **({'ecosystem': dep.get('ecosystem'),
            'package': dep.get('name'), 'version': dep.get('version'), 'manifest': dep.get('manifest')} if dep else {})}
        result['gaps'].append(value)
        if run_context is not None and (selected_required if selected is None else selected):
            run_context.gaps.append(value)

    try:
        if not isinstance(inventory, dict) or inventory.get('complete') is not True or inventory.get('gaps'):
            raise ArtifactError('license-inventory-incomplete', 'package and artifact inventory is incomplete')
        dependencies, tools, images = (inventory.get(name) for name in ('dependencies', 'tools', 'images'))
        if not all(isinstance(values, list) and all(isinstance(item, dict) for item in values) for values in (dependencies, tools, images)):
            raise ArtifactError('license-inventory-incomplete', 'inventory artifact families are malformed or missing')
        if not isinstance(inventory.get('marker_environment', {}), dict):
            raise ArtifactError('license-transitive-coverage', 'observed target marker environment must be a mapping')
        if not dependencies and not tools and not images:
            return {**result, 'status': 'skip', 'summary': 'complete inventory has no applicable third-party artifacts'}
        policy = _policy(policy)
        result['policy_digest'] = policy['digest']
        factory_scope = None
        if _factory_parent_binding is not None:
            from .security_python_target import _binding
            from .security_factory_inputs import verify as verify_factory, PROFILE
            _binding(_factory_parent_binding)
            auxiliary = verify_factory(artifacts.parent, _factory_parent_binding, policy, now=now)
            if auxiliary['inventory'] != inventory or auxiliary['root'] != artifacts:
                raise ArtifactError('license-exception-conditions', 'Factory exception scope differs from actual verified output')
            factory_scope = dict(manifest_sha256=_factory_parent_binding['factory_inputs']['policy_profile']['lock_sha256'],
                profile=PROFILE, abi='cp312-cp312-manylinux_2_17_x86_64', delivery_kind='factory-offline-archive')
        if target_binding is not None:
            from .security_python_target import _binding
            _binding(target_binding)
            if target_binding['inventory_sha256'] != inventory.get('digest'):
                raise ArtifactError('artifact-inventory-binding', 'Python target belongs to another source inventory')
            result['python_target_scope'] = {'target':target_binding['target'],
                'assurance':('one observed CI installation; no final runtime integrity claim' if 'ci_consumer' in target_binding
                    else 'current-interpreter-only; no unobserved target or final-delivery credit')}
            if 'ci_uses' in target_binding:
                result['observed_ci_uses']=target_binding['ci_uses']
            if policy.get('factory_offline_profile') and 'factory_inputs' not in target_binding and any(
                    dep.get('manifest','').startswith('factory/') for dep in dependencies):
                gap('artifact-target-scope-unobserved',
                    'current interpreter observation does not qualify the separate Factory offline target and final delivery')
        raw = read_file(artifacts, 'manifest.json', MAX_INDEX_BYTES)
        bundle = _json(raw)
        if bundle.get('schema_version') != 1 or type(bundle.get('schema_version')) is not int:
            raise ArtifactError('artifact-manifest', 'unsupported artifact manifest schema')
        digest = inventory.get('digest')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None or bundle.get('inventory_digest') != digest:
            raise ArtifactError('artifact-inventory-binding', 'artifact manifest belongs to another inventory')
        current = _clock(now)
        age = (current - _timestamp(bundle.get('last_verified_sync_utc'))).total_seconds()
        if age < 0 or age > MAX_AGE_SECONDS:
            raise ArtifactError('artifact-stale', 'artifact acquisition is future-dated or older than 72 hours')
        records = bundle.get('records')
        if not isinstance(records, list) or len(records) > 10000 or not all(isinstance(record, dict) for record in records):
            raise ArtifactError('artifact-manifest', 'artifact manifest records are malformed')
        if bundle.get('gaps'):
            gap('artifact-acquisition-incomplete', 'artifact producer reported incomplete acquisition')
        indexed = {}
        for record in records:
            key = artifact_identity(record)
            if 'kind' in record and record['subject'] not in (images if record['kind'] == 'image' else tools):
                raise ArtifactError('artifact-inventory-binding', 'family record is not owned by this source inventory')
            if key in indexed:
                raise ArtifactError('artifact-manifest', 'duplicate exact artifact/source/use identity')
            indexed[key] = record
        deliveries = verify_deliveries(artifacts, bundle.get('deliveries', []), records, dependencies,
            corresponding_source_delivery=inventory.get('corresponding_source_delivery'))
        result['source_evidence'] = {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'last_verified_sync_utc': bundle['last_verified_sync_utc'], 'age_seconds': age,
            'checked_at_utc': current.isoformat(), 'coverage': {'declared_packages': len(indexed)}}
        if target_binding is not None and 'factory_inputs' in target_binding:
            from .security_factory_inputs import verify
            auxiliary=verify(artifacts,target_binding,policy,now=now)
            output=evaluate_artifacts(auxiliary['inventory'],auxiliary['root'],policy,now=now, _factory_parent_binding=target_binding)
            result['factory_output']={'profile':target_binding['factory_inputs']['profile'],
                'status':output['status'],'source_evidence':output.get('source_evidence'),
                'assurance':'named Factory output only; original source uses remain separate'}
            result['details'].extend(output['details'])
            result['gaps'].extend(output['gaps'])
            if run_context is not None:
                run_context.auxiliary('factory-output',output)
        ci_proved={}
        if target_binding is not None and 'ci_uses' in target_binding and 'ci_consumer' not in target_binding:
            from .security_ci_inputs import verify as verify_ci
            result['ci_installations']=[]
            for index,consumer in enumerate(target_binding['ci_uses']['consumers']):
                if consumer.get('image_target_observed') is not True:
                    continue
                auxiliary=verify_ci(artifacts,target_binding,index,policy,now=now)
                from .security_python_target import digest as subject_digest, _subject
                ci_proved[index]={subject_digest(_subject(dep)) for dep in auxiliary['inventory']['dependencies']}
                output=evaluate_artifacts(auxiliary['inventory'],auxiliary['root'],policy,now=now,target_binding=auxiliary['binding'])
                result['ci_installations'].append(dict(image=consumer['image'],status=output['status'],
                    source_evidence=output.get('source_evidence'),assurance='isolated CI installation only; original scopes remain'))
                result['details'].extend(output['details'])
                result['gaps'].extend(output['gaps'])
                if run_context is not None:
                    run_context.auxiliary('ci-install:'+consumer['build_sha256'],output)
                    if output['status'] == 'pass':
                        run_context.build_inputs(auxiliary['binding'],output)
        if run_context is not None and any(row['kind'] == 'checker-tool' for row in run_context.required.values()):
            result['checker_tools'] = run_context.checker_inputs(artifacts, policy, now=now)
        for subject, kind in [*((item, 'action' if item.get('kind') == 'github-action' else 'tool') for item in tools),
                              *((item, 'image') for item in images)]:
            selected_required=run_context is not None and run_context.family_required(subject,kind)
            try:
                record = select_family(subject, kind, records)
                evidence = family_evidence(artifacts, record)
                _family_age(record, current, bundle['last_verified_sync_utc'])
                raw_distribution = _distribution_for(subject, policy['usage_distribution'])
                distribution=raw_distribution
                referenced = kind == 'image' and evidence.get('held_image') and 'referenced_output_sha256' in evidence and 'referenced_image_scope' in policy
                if referenced:
                    raw_distribution = distribution = 'referenced'
                elif selected_required:
                    distribution=run_context.family_distribution(subject,kind)
                    if raw_distribution!='internal':
                        gap('license-obligation-missing','raw/future family use remains separate from the actual internal CI use',selected=False)
                elif distribution != 'internal':
                    raise ArtifactError('license-obligation-missing', 'family needs explicit internal use or a qualified final-output adapter')
                selected, licenses, notices = [], [], []
                for component in evidence['components']:
                    if evidence.get("held_image") and component.get("license_status") in {"internal-report-only", "referenced-report-only"}:
                        if ("image_license_scope" not in policy or distribution not in {"internal", "referenced"}
                                or component["license_status"] != distribution + "-report-only"
                                or not evidence.get("license_observations") or component["expression"] is not None):
                            raise ArtifactError("license-obligation-missing", "internal observation outside its licensed scope")
                        if any(not evidence['files'].get(path, b'').strip() for path in component['notice_paths']):
                            raise ArtifactError('license-obligation-missing', 'declared component NOTICE is empty')
                        continue
                    from .security_license_family_conditions import allowed_for
                    component_allowed = allowed_for(record, component, policy['auto_allow'],
                        selected_internal=distribution == 'internal' and (selected_required or
                            record['origin'].get('kind') == 'go-checker-release/v1' and
                            'go_module_sources' in evidence['binding']),
                        source_modules=evidence['binding'].get('go_module_sources', []))
                    chosen, identifiers = _select_expression(component['expression'], component_allowed)
                    owned = {item['path'] for item in component['files']}
                    shared = set(component['license_paths'] + component['notice_paths']) if evidence.get('held_image') else set()
                    files = {name: body for name, body in evidence['files'].items() if name in owned | shared}
                    license_files, notice_files = _license_evidence(files, component, identifiers, chosen)
                    if any(not files.get(path, b'').strip() for path in component['notice_paths']):
                        raise ArtifactError('license-obligation-missing', 'declared component NOTICE is empty')
                    selected.extend(chosen)
                    licenses.extend(license_files)
                    notices.extend(notice_files)
                detail={'kind': kind, 'reference': subject['reference'], 'status': 'pass',
                    'selected_expression': ' AND '.join(sorted(set(selected))), 'distribution': distribution,
                    **evidence['binding'], 'family_record': record,
                    'component_inventory_json': read_file(artifacts,record['components']['path'],MAX_INDEX_BYTES).decode('utf-8'),
                    'license_files': licenses, 'notice_files': notices,
                    'obligations': distribution + ' use; exact source/component/license evidence retained'}
                if "license_observations" in evidence:
                    if ("image_license_scope" not in policy or distribution not in {"internal", "referenced"}
                            or evidence["license_observations"]["status"] != distribution + "-report-only"):
                        raise ArtifactError("license-obligation-missing", "internal observation requires its scope decision")
                    detail.update(license_observations=evidence["license_observations"],
                                  obligations=distribution + " use; partial license evidence reported")
                if raw_distribution in {'internal', 'referenced'}:
                    result['details'].append(detail)
                if selected_required:
                    if kind == 'action' and distribution == 'internal':
                        from .security_action_inputs import mark_selected_internal_family
                        mark_selected_internal_family(record)
                    run_context.family_passed(subject,kind,detail)
            except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError) as exc:
                code = getattr(exc, 'code', 'artifact-invalid')
                if code == 'license-artifact-missing':
                    code = 'license-image-coverage' if kind == 'image' else 'license-tool-coverage'
                gap(code, str(exc))
        for dep in dependencies:
            selected_required=run_context is not None and run_context.dependency_required(dep)
            try:
                if dep.get('ecosystem') == 'PyPI':
                    _extras(dep.get('extras', []))
                distribution = _distribution_for(dep, policy['usage_distribution'])
                scope_known = isinstance(distribution, str) and distribution in {'internal', 'redistributed'}
                if not scope_known:
                    gap('license-scope-unknown', 'use/distribution scope requires an observed project decision', dep)
                key = package_key(dep.get('ecosystem'), dep.get('name'), dep.get('version'))
                record = select_artifact(dep, records)
                if 'acquired_at' in record:
                    _family_age(record, current, bundle['last_verified_sync_utc'])
                payload = read_file(artifacts, record.get('path'), MAX_ARTIFACT_BYTES)
                origin = verify_origin(artifacts, record, payload)
                if dep.get('artifact_sha256') and dep['artifact_sha256'] != record['sha256']:
                    raise ArtifactError('artifact-identity', 'artifact differs from the observed dependency artifact')
                if dep.get('artifact_filename') and dep['artifact_filename'] != record['filename']:
                    raise ArtifactError('artifact-identity', 'artifact filename differs from the observed target')
                observed = None
                ci_image_target_gap=False
                if dep['ecosystem'] == 'PyPI' and (target_binding is not None or 'python_target' in record):
                    from .security_python_target import verify_record
                    observed = verify_record(record,payload,target_binding,dependency=dep)
                    if target_binding and 'source_pins' in target_binding and not target_binding['source_pins'][observed['subject_sha256']]['marker_active']:
                        raise ArtifactError('artifact-target-use-unobserved', 'this source marker requires a separately observed target; current input bytes grant no other-target use credit')
                    ci=target_binding.get('ci_uses',{})
                    if ('ci_consumer' not in target_binding and observed.get('subject_sha256') in ci.get('subjects',{})
                            and not all(observed['subject_sha256'] in ci_proved.get(index,set())
                                for index in ci['subjects'][observed['subject_sha256']])):
                        # Existing #323 internal CI decision applies to this actual consumer only.
                        # The original production/customer source-use row remains separate above.
                        ci_image_target_gap=True
                        gap('artifact-target-use-unobserved',
                            'actual isolated CI consumer has internal use; its image interpreter/libc target is not the host observation',dep)
                if dep['ecosystem'] == 'PyPI' and observed is None and not (dep.get('artifact_filename') or dep.get('artifact_sha256')):
                    if not re.search(r'-(?:py3|py2\.py3)-none-any\.whl$', record['filename']):
                        raise ArtifactError('artifact-target-unknown', 'platform wheel or sdist requires an explicitly observed artifact target')
                files = archive_files(payload, record['filename'])
                metadata = package_metadata(files, dep['ecosystem'], record['filename'],
                                            **({'origin': origin} if dep['ecosystem'] == 'Packagist' else {}))
                missing_paths = set(metadata['license_paths']) - set(files)
                if missing_paths:
                    files.update(archive_files(payload, record['filename'], requested=missing_paths))
                if package_key(dep['ecosystem'], metadata['name'], metadata['version']) != key:
                    raise ArtifactError('artifact-identity', 'artifact metadata Name/Version differs from inventory')
                _validate_extra_scope(metadata, dep)
                exception = None
                required_retention = []
                try:
                    chosen, identifiers = _select_expression(metadata['expression'], policy['auto_allow'])
                    if dep['ecosystem'] == 'Packagist':
                        from .security_packagist import license_members
                        license_inputs = license_members(files, metadata)
                    else:
                        license_inputs = files
                    license_files, notice_files = _license_evidence(license_inputs, metadata, identifiers, chosen,
                        final_wheel=dep['ecosystem']=='PyPI' and record['filename'].endswith('.whl'))
                except ArtifactError as original:
                    from .security_license_exceptions import PROFILES, matching_profile, retention_paths, scope_for, verify_exception
                    requested = retention_paths(policy,dep)
                    if not requested:
                        raise
                    try:
                        if requested - set(files):
                            files.update(archive_files(payload,record['filename'],requested=requested-set(files)))
                        scope = factory_scope if factory_scope is not None else scope_for(dep,target_binding,observed)
                        supplements = None
                        if target_binding is not None and 'ci_consumer' in target_binding:
                            condition = matching_profile(policy,dep,record,distribution,scope)
                            if PROFILES[condition].get('supplements'):
                                from .security_license_supplements import prove_ci
                                supplements = prove_ci(target_binding,dep,record,scope,condition)
                        exception = verify_exception(policy,dep,record,files,metadata,distribution,scope,supplements=supplements)
                    except ArtifactError as condition:
                        raise ArtifactError(condition.code, str(condition)+'; original license diagnostic ['+original.code+']: '+str(original)) from condition
                    exception['detail']['original_diagnostic'] = dict(code=original.code,message=str(original))
                    chosen = [metadata['expression']]
                    license_files, notice_files = exception['license_files'], exception['notice_files']
                    required_retention = exception['required_retention']
                custody = None
                context = dep.get('delivery_context')
                if target_binding is not None and 'ci_consumer' in target_binding:
                    from .security_ci_inputs import verify_custody
                    custody=verify_custody(target_binding,dep,files,sorted(set(required_retention)|{item['path'] for item in license_files+notice_files}))
                if dep.get('delivery_kind') == 'factory-offline-archive' and context not in deliveries:
                    raise ArtifactError('license-obligation-missing', 'offline archive requires actual final output and composition evidence')
                if context in deliveries:
                    if distribution != 'redistributed':
                        raise ArtifactError('license-scope-conflict', 'named archive components must retain redistributed scope')
                    output = deliveries[context]
                    retained = sorted('site-packages/' + path for path in set(required_retention)|{item['path'] for item in license_files + notice_files})
                    custody = {field: value for field, value in output.items() if field != 'members'}
                    custody['retained_members'] = retained
                elif distribution == 'redistributed':
                    if context and dep.get('delivery_kind') != 'unchanged-artifact':
                        raise ArtifactError('license-obligation-missing', 'named output needs its actual final delivery and composition evidence')
                    delivery = record.get('redistributed_path')
                    if not delivery:
                        raise ArtifactError('license-obligation-missing', 'redistribution needs evidence of the unchanged delivered artifact retaining LICENSE/NOTICE')
                    delivered = read_file(artifacts, delivery, MAX_ARTIFACT_BYTES)
                    if hashlib.sha256(delivered).hexdigest() != record['sha256']:
                        raise ArtifactError('license-obligation-missing', 'modified delivery needs separate notice, attribution and license review')
                markers = (target_binding['target']['marker_environment'] if observed is not None else inventory.get('marker_environment', {}))
                if observed is not None:
                    from .security_python_target import closure_dependencies
                    for graph in closure_dependencies(dep,dependencies,target_binding):
                        _closure(metadata,dep,graph,markers)
                else:
                    _closure(metadata, dep, dependencies, markers)
                if not scope_known or ci_image_target_gap:
                    continue
                result['details'].append({'ecosystem': dep['ecosystem'], 'package': dep['name'], 'version': dep['version'],
                    'manifest': dep.get('manifest'), 'status': 'pass', 'expression': metadata['expression'],
                    'selected_expression': ' AND '.join(chosen), 'distribution': distribution,
                    'artifact_sha256': record['sha256'], 'artifact_id': artifact_identity(record),
                    'context': {**record.get('context', {}), **({'python_target_sha256':observed['target_sha256']} if observed else {})}, **({'delivery': custody} if custody else {}),
                    'origin': origin, **({'policy_exception':exception['detail']} if exception else {}), 'license_files': license_files,
                    'notice_files': notice_files, 'obligations': ('retained in final extracted archive' if custody else 'retained in exact artifact')
                    if distribution == 'redistributed' else 'internal use; license evidence retained'})
                if selected_required:
                    run_context.package_passed(dep,result['details'][-1])
            except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError, VulnerabilityError) as exc:
                gap(getattr(exc, 'code', 'artifact-invalid'), str(exc), dep)
    except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError, VulnerabilityError) as exc:
        gap(getattr(exc, 'code', 'artifact-invalid'), str(exc))
    result['status'] = 'fail' if result['gaps'] else 'pass'
    result['summary'] = (f"{len(result['gaps'])} artifact license, scope or coverage gaps require resolution" if result['gaps']
                         else f"license policy and retained evidence verified for {len(result['details'])} exact package artifacts")
    if run_context is not None:
        return run_context.finish(result)
    if result['status'] == 'pass' and target_binding is not None and 'ci_consumer' in target_binding:
        from . import security_ci_inputs
        security_ci_inputs.seal_evaluation(target_binding,result,_entry=security_ci_inputs._EVALUATION_ENTRY)
    return result
