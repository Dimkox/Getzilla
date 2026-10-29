from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .architecture import architecture_inputs_present, preflight_architecture
from .manifest import verify_manifest
from .repo import detect_repo
from .router import build_route
from .toolchain import check_toolchain
from .util import load_json


@dataclass
class DoctorItem:
    status: str
    name: str
    message: str


def _engine_archive_item(archive: Path) -> DoctorItem:
    """The archive carries bytecode for the Python that installed it; another Python reads the sources."""
    import importlib.util
    import zipfile
    try:
        with zipfile.ZipFile(archive) as bundle:
            header = bundle.read('getzilla/policy.pyc')[:4]
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        return DoctorItem('fail', 'engine-archive', f'unreadable: {exc}')
    if header != importlib.util.MAGIC_NUMBER:
        return DoctorItem('warn', 'engine-archive', 'bytecode is for another Python, so hooks compile the engine '
                          'on every call; reinstall Getzilla into this project with the current Python')
    return DoctorItem('pass', 'engine-archive', 'engine archive with bytecode for this Python')


def run_doctor(root: Path) -> list[DoctorItem]:
    items: list[DoctorItem] = []

    required = [
        'AGENTS.md', '.grok/config.toml', '.grok/hooks.json',
        '.agents/skills/getzilla-delivery/SKILL.md', '.getzilla/config/routing.json',
    ]
    for rel in required:
        items.append(DoctorItem('pass' if (root / rel).exists() else 'fail', f'file:{rel}', 'present' if (root / rel).exists() else 'missing'))

    for rel in ('.grok/config.toml',):
        try:
            tomllib.loads((root / rel).read_text(encoding='utf-8'))
            items.append(DoctorItem('pass', f'toml:{rel}', 'valid TOML'))
        except Exception as exc:
            items.append(DoctorItem('fail', f'toml:{rel}', str(exc)))

    for rel in ('.grok/hooks.json', '.qwen/settings.json', '.claude/settings.json', '.codex/hooks.json',
                '.gemini/settings.json', '.github/hooks/getzilla.json'):
        if rel != '.grok/hooks.json' and not (root / rel).exists():
            items.append(DoctorItem('info', f'json:{rel}', 'harness not installed'))
            continue
        try:
            json.loads((root / rel).read_text(encoding='utf-8'))
            items.append(DoctorItem('pass', f'json:{rel}', 'valid JSON'))
        except Exception as exc:
            items.append(DoctorItem('fail', f'json:{rel}', str(exc)))

    archive = root / '.getzilla/getzilla.zip'
    if archive.is_file():
        items.append(_engine_archive_item(archive))

    managed = load_json(root / '.getzilla/config/managed.json', {}) or {}
    managed_agents = managed.get('agents', [])
    managed_skills = managed.get('skills', [])
    extra_skills = managed.get('extra_skills') if isinstance(managed.get('extra_skills'), dict) else {}
    extra_agents = managed.get('extra_agents') if isinstance(managed.get('extra_agents'), dict) else {}

    for name in managed_agents:
        path = root / '.grok/agents' / f'{name}.toml'
        if not path.is_file():
            if name in extra_agents:
                items.append(DoctorItem('info', f'agent:{name}', f'not installed; add it with getzilla components add {extra_agents[name]}'))
            else:
                items.append(DoctorItem('fail', f'agent:{name}', 'managed agent is missing'))
            continue
        try:
            data = tomllib.loads(path.read_text(encoding='utf-8'))
            missing = [key for key in ('name', 'description', 'developer_instructions') if not data.get(key)]
            items.append(DoctorItem('fail' if missing else 'pass', f'agent:{path.name}', f'missing {missing}' if missing else data['name']))
        except Exception as exc:
            items.append(DoctorItem('fail', f'agent:{path.name}', str(exc)))

    for name in managed_skills:
        path = root / '.agents/skills' / name / 'SKILL.md'
        if not path.is_file():
            if name in extra_skills:
                items.append(DoctorItem('info', f'skill:{name}', f'not installed; add it with getzilla components add {extra_skills[name]}'))
            else:
                items.append(DoctorItem('fail', f'skill:{name}', 'managed skill is missing'))
            continue
        skill_text = path.read_text(encoding='utf-8')
        valid = skill_text.startswith('---\n') and '\nname:' in skill_text[:500] and '\ndescription:' in skill_text[:1000]
        items.append(DoctorItem('pass' if valid else 'fail', f'skill:{name}', 'valid frontmatter' if valid else 'invalid frontmatter'))

    unmanaged_agents = [path.name for path in (root / '.grok/agents').glob('*.toml') if path.stem not in managed_agents]
    unmanaged_skills = [path.parent.name for path in (root / '.agents/skills').glob('*/SKILL.md')
                        if path.parent.name not in managed_skills and path.parent.name not in extra_skills]
    if unmanaged_agents:
        items.append(DoctorItem('info', 'unmanaged-agents', ', '.join(sorted(unmanaged_agents))))
    if unmanaged_skills:
        items.append(DoctorItem('info', 'unmanaged-skills', ', '.join(sorted(unmanaged_skills))))

    profile = detect_repo(root)
    items.append(DoctorItem('pass', 'repo-detection', f'{profile.kind}; domains={profile.domains}; signals={profile.signals[:5]}'))
    sample = build_route(root, 'Исправить ошибку в обработчике события Битрикс D7 и добавить PHPUnit тест', 'doctor')
    # The project's routing.json may add review floors (test_reviewer, for example), so only the
    # first reviewer is fixed; the rest belong to the project, not to this self-test.
    expected = {'write_agent': 'bitrix_implementer', 'first reviewer': 'code_reviewer', 'risk_assessment.status': 'provisional'}
    actual = {'write_agent': sample.write_agent, 'first reviewer': next(iter(sample.review_agents), None),
              'risk_assessment.status': sample.risk_assessment.get('status')}
    differ = [f'{key}: expected {expected[key]!r}, got {actual[key]!r}' for key in expected if actual[key] != expected[key]]
    if differ:
        items.append(DoctorItem('fail', 'adaptive-routing', '; '.join(differ)))
    else:
        items.append(DoctorItem('pass', 'adaptive-routing', 'Bitrix route selects specialized agents'))

    if not architecture_inputs_present(root):
        items.append(DoctorItem('info', 'architecture-model', 'architecture documents are not present; skipped'))
    else:
        findings = preflight_architecture(root)
        items.append(DoctorItem(
            'fail' if findings else 'pass', 'architecture-model',
            findings[0].message if findings else 'bounded model and referenced-input preflight passed',
        ))

    manifest_path = root / 'MANIFEST.sha256'
    if manifest_path.is_file():
        manifest_errors = verify_manifest(root)
        items.append(DoctorItem(
            'fail' if manifest_errors else 'pass',
            'manifest',
            '; '.join(manifest_errors[:10]) if manifest_errors else 'all packaged files match MANIFEST.sha256',
        ))
    else:
        items.append(DoctorItem('info', 'manifest', 'not generated yet; packaging creates it'))

    for tool in check_toolchain(root):
        items.append(DoctorItem(tool.status, f'tool:{tool.id}', tool.message))
    return items
