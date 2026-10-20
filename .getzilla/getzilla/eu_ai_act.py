"""EU AI Act evidence gate: an optional component, off unless the project installs it.

The component (``compliance:eu-ai-act``) ships the obligation matrix. The project keeps its own
register of AI systems in ``.getzilla/config/ai-systems.json``, a control-plane path that agents
cannot write without an exact grant. A risk class is a draft until a named person confirms it:
the classifier proposes, a human decides. Evidence comes from the repository at the checked
commit (symbols in the code and in tests, a risk register), never from the agent's own claim.
Engineering evidence only, not legal advice.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

OBLIGATIONS = '.getzilla/compliance/eu-ai-act/obligations.json'
REGISTRY = '.getzilla/config/ai-systems.json'
# Written only by the installer (--compliance) or `getzilla components add`; never shipped as payload.
COMPLIANCE_CONFIG = '.getzilla/config/compliance.json'
CLASSES = ('prohibited', 'high-risk', 'limited', 'minimal')
RANK = {name: index for index, name in enumerate(reversed(CLASSES))}  # minimal 0 ... prohibited 3
RISK_REVIEW_DAYS = 365

# Draft classification from the declared purpose. Words in English and Russian; a match proposes,
# it never decides. Order matters: the most restrictive class wins.
_DRAFT_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ('prohibited', 'social scoring', re.compile(r'social\s+scor|социальн\w*\s+рейтинг', re.I)),
    ('prohibited', 'subliminal or manipulative technique', re.compile(r'sublimina|manipulat\w*\s+(?:behaviou?r|vulnerab)|манипуляц', re.I)),
    ('prohibited', 'untargeted facial image scraping', re.compile(r'(?:scrap\w*|untargeted)\W+(?:\w+\W+){0,3}facial|facial\W+(?:\w+\W+){0,3}scrap', re.I)),
    ('prohibited', 'emotion recognition at work or school', re.compile(r'emotion\w*\s+recogn\w*.{0,40}(?:workplace|employee|school|student)|распознаван\w*\s+эмоци', re.I)),
    ('high-risk', 'creditworthiness or credit scoring (Annex III 5(b))', re.compile(r'credit\s*(?:worth|scor)|creditworth|loan\s+(?:approv|decision|applicant)|borrower|кредитн\w*\s+(?:скоринг|рейтинг|оценк)|заёмщик|заемщик', re.I)),
    ('high-risk', 'recruitment, selection or worker management (Annex III 4)', re.compile(r'recruit|hiring|candidate\s+(?:screen|rank)|cv\s+screen|résumé|resume\s+screen|employee\s+(?:evaluat|monitor)|подбор\s+персонала|найм|кандидат\w*\s+на\s+вакан', re.I)),
    ('high-risk', 'education access or assessment (Annex III 3)', re.compile(r'(?:exam|admission|student)\w*\s+(?:scor|grad|assess|proctor)|proctoring|приём\s+в\s+вуз|оценк\w*\s+студент', re.I)),
    ('high-risk', 'biometric identification or categorisation (Annex III 1)', re.compile(r'biometric|face\s+(?:recogn|identif)|биометр|распознаван\w*\s+лиц', re.I)),
    ('high-risk', 'access to essential public or private services (Annex III 5)', re.compile(r'(?:benefit|insurance|health\s+insurance)\s+(?:eligib|pric|risk)|страхов\w*\s+(?:риск|тариф)', re.I)),
    ('limited', 'generates content or talks to people (Art. 50)', re.compile(r'chat\s*bot|assistant|generat\w*\s+(?:text|image|video|audio|content|answer|repl)|deep\s*fake|synthetic\s+(?:media|voice|image)|ассистент|чат-?бот|генерац\w*\s+(?:текст|изображ|видео|контент|ответ)', re.I)),
)


@dataclass(frozen=True)
class Draft:
    risk_class: str
    reasons: tuple[str, ...]


def draft_class(purpose: str) -> Draft:
    """Proposed AI Act class for a declared purpose; ``minimal`` when nothing matches."""
    hits = [(risk_class, reason) for risk_class, reason, pattern in _DRAFT_RULES if pattern.search(purpose or '')]
    if not hits:
        return Draft('minimal', ())
    top = max(RANK[risk_class] for risk_class, _ in hits)
    chosen = next(risk_class for risk_class, _ in hits if RANK[risk_class] == top)
    return Draft(chosen, tuple(reason for risk_class, reason in hits if risk_class == chosen))


def enabled(root: Path) -> bool:
    """The project opted in: the matrix is installed and compliance.json enables eu-ai-act.

    The Getzilla source and any copy of it carry the matrix but no opt-in record, so they never gate.
    """
    if not (root / OBLIGATIONS).is_file():
        return False
    try:
        config = json.loads((root / COMPLIANCE_CONFIG).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return isinstance(config, dict) and 'eu-ai-act' in (config.get('enabled') or [])


def opt_in_record(layers: Iterable[str]) -> bytes:
    data = {'schema_version': 'getzilla-compliance-v1', 'enabled': sorted(set(layers))}
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode('utf-8')


def load_obligations(root: Path) -> list[dict[str, Any]]:
    data = json.loads((root / OBLIGATIONS).read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema_version') != 'eu-ai-act-obligations-v1':
        raise ValueError(f'{OBLIGATIONS}: schema_version must be eu-ai-act-obligations-v1')
    obligations = data.get('obligations')
    if not isinstance(obligations, list) or not obligations:
        raise ValueError(f'{OBLIGATIONS}: obligations must be a non-empty list')
    return obligations


def load_registry(root: Path) -> list[dict[str, Any]]:
    path = root / REGISTRY
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema_version') != 'ai-systems-v1' or not isinstance(data.get('systems'), list):
        raise ValueError(f'{REGISTRY}: expected {{"schema_version": "ai-systems-v1", "systems": [...]}}')
    return [system for system in data['systems'] if isinstance(system, dict)]


@dataclass
class Report:
    status: str
    summary: str
    problems: list[str] = field(default_factory=list)
    matrix: list[dict[str, str]] = field(default_factory=list)
    systems: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'status': self.status, 'summary': self.summary, 'problems': self.problems,
                'matrix': self.matrix, 'systems': self.systems}


def _git_files(root: Path, head: str) -> list[str]:
    from .project_ingestion import _git
    listing = _git(root, 'ls-tree', '-r', '--name-only', '-z', head).stdout.decode('utf-8', 'surrogateescape')
    return [item for item in listing.split('\0') if item]


def _blob(root: Path, head: str, path: str) -> str | None:
    from .project_ingestion import _git
    shown = _git(root, 'show', f'{head}:{path}', check=False)
    return shown.stdout.decode('utf-8', 'replace') if shown.returncode == 0 else None


def _owned(path: str, system: dict[str, Any]) -> bool:
    return any(isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in system.get('paths') or [])


def _confirmation_problem(system: dict[str, Any]) -> str | None:
    confirmation = system.get('confirmation')
    if not isinstance(confirmation, dict):
        return 'no confirmation'
    for key in ('by', 'role'):
        if not isinstance(confirmation.get(key), str) or len(confirmation[key].strip()) < 2:
            return f'confirmation.{key} is missing'
    try:
        date.fromisoformat(str(confirmation.get('date')))
    except ValueError:
        return 'confirmation.date must be YYYY-MM-DD'
    return None


def _symbol_tested(root: Path, head: str, symbol: Any, code: list[str], tests: list[str]) -> str | None:
    if not isinstance(symbol, str) or not symbol.isidentifier():
        return 'no code symbol declared'
    pattern = re.compile(r'(?<![\w])' + re.escape(symbol) + r'(?![\w])')
    if not any(pattern.search(_blob(root, head, path) or '') for path in code):
        return f'{symbol} is not in the system code'
    if not any(pattern.search(_blob(root, head, path) or '') for path in tests):
        return f'{symbol} is not exercised by a test'
    return None


def _risk_register_problem(root: Path, head: str, path: Any, today: date) -> str | None:
    if not isinstance(path, str) or not path:
        return 'no risk_register path declared'
    text = _blob(root, head, path)
    if text is None:
        return f'{path} is not committed'
    try:
        risks = json.loads(text).get('risks')
    except (ValueError, AttributeError):
        return f'{path} is not a JSON object with "risks"'
    if not isinstance(risks, list) or not risks:
        return f'{path} lists no risks'
    for index, risk in enumerate(risks):
        if not isinstance(risk, dict) or not all(isinstance(risk.get(key), str) and risk[key].strip()
                                                for key in ('risk', 'mitigation', 'owner', 'reviewed')):
            return f'{path} risk {index} needs risk, mitigation, owner and reviewed'
        try:
            age = (today - date.fromisoformat(risk['reviewed'])).days
        except ValueError:
            return f'{path} risk {index}: reviewed must be YYYY-MM-DD'
        if age > RISK_REVIEW_DAYS:
            return f'{path} risk {index} was last reviewed {age} days ago (limit {RISK_REVIEW_DAYS})'
    return None


def evaluate(root: Path, mode: str, bases: Iterable[str], head: str = 'HEAD', *, today: date | None = None) -> Report:
    if not enabled(root):
        return Report('skip', 'EU AI Act component not installed')
    from . import cost_guard
    from .diff_risk import load_rules, matches
    strict = mode in {'pr', 'release'}
    today = today or datetime.now(timezone.utc).date()
    obligations = load_obligations(root)
    systems = load_registry(root)
    files = _git_files(root, head)
    test_globs = load_rules()['tests']
    tests = [path for path in files if matches(path, test_globs)]
    problems: list[str] = []
    matrix: list[dict[str, str]] = []
    ai_paths = sorted({finding.path for base in bases for finding in cost_guard.diff_cost_findings(root, base, head)})
    for path in ai_paths:
        if not matches(path, test_globs) and not any(_owned(path, system) for system in systems):
            problems.append(f'AI_SYSTEM_UNREGISTERED: {path} calls an AI provider but no system in {REGISTRY} owns it')
    summaries = []
    for system in systems:
        name = str(system.get('id') or '?')
        draft = draft_class(str(system.get('purpose') or ''))
        risk_class = system.get('class')
        summaries.append({'id': name, 'class': risk_class, 'draft_class': draft.risk_class, 'draft_reasons': list(draft.reasons)})
        if risk_class not in CLASSES:
            problems.append(f'AI_CLASS_UNCONFIRMED: {name} has no class; draft is {draft.risk_class}'
                            + (f' ({"; ".join(draft.reasons)})' if draft.reasons else ''))
            continue
        unconfirmed = _confirmation_problem(system)
        if unconfirmed:
            problems.append(f'AI_CLASS_UNCONFIRMED: {name} class {risk_class}: {unconfirmed}; a person confirms the class, the agent never does')
        if RANK[risk_class] < RANK[draft.risk_class] and not str(system.get('downgrade_reason') or '').strip():
            problems.append(f'AI_CLASS_BELOW_DRAFT: {name} is {risk_class} but the draft is {draft.risk_class}; '
                            'record downgrade_reason with the legal basis')
        if risk_class == 'prohibited':
            problems.append(f'AI_PROHIBITED_PRACTICE: {name} is classified prohibited (Art. 5) and cannot ship')
        code = [path for path in files if _owned(path, system) and not matches(path, test_globs)]
        for obligation in obligations:
            row = {'obligation': str(obligation.get('id')), 'article': str(obligation.get('article')), 'system': name}
            if risk_class not in (obligation.get('applies_to') or []) or (
                    obligation.get('when') == 'generates_content' and system.get('generates_content') is False):
                matrix.append({**row, 'status': 'not_applicable', 'evidence': f'class {risk_class}'})
                continue
            check = obligation.get('check')
            gap: str | None
            evidence: str
            if check == 'classification':
                gap = unconfirmed if risk_class != 'prohibited' else 'prohibited practice'
                evidence = f'class {risk_class} confirmed by {(system.get("confirmation") or {}).get("by", "?")}'
            elif check == 'tested_symbol':
                fieldname = str(obligation.get('field'))
                gap = _symbol_tested(root, head, system.get(fieldname), code, tests)
                evidence = f'{fieldname}={system.get(fieldname)} in code and tests'
            elif check == 'risk_register':
                gap = _risk_register_problem(root, head, system.get('risk_register'), today)
                evidence = f'risk register {system.get("risk_register")}'
            elif check == 'audit_bundle':
                gap, evidence = None, 'technical documentation is the release audit bundle (scripts/getzilla_audit_bundle.py)'
                matrix.append({**row, 'status': 'at_release', 'evidence': evidence})
                continue
            elif check == 'verify':
                gap, evidence = None, 'this verification run: tests, security and dependency checks'
                matrix.append({**row, 'status': 'covered_by_verify', 'evidence': evidence})
                continue
            else:
                gap, evidence = f'unknown check {check!r}', ''
            if gap:
                problems.append(f'OBLIGATION_UNMET: {name} {row["obligation"]} ({row["article"]}): {gap}')
                matrix.append({**row, 'status': 'unmet', 'evidence': gap})
            else:
                matrix.append({**row, 'status': 'met', 'evidence': evidence})
    if not systems and not ai_paths:
        return Report('pass', 'EU AI Act: no AI system registered and no AI provider call in the change', [], matrix, summaries)
    if problems:
        status = 'fail' if strict else 'pass'
        prefix = '' if strict else 'will fail pr/release: '
        return Report(status, prefix + problems[0], problems, matrix, summaries)
    met = sum(1 for row in matrix if row['status'] == 'met')
    return Report('pass', f'EU AI Act: {len(systems)} system(s), {met} obligation(s) met with evidence', [], matrix, summaries)
