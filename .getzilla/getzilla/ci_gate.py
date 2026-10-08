"""Choose a repository's CI/merge gate from its GitHub visibility.

Owner rule of 2026-10-06: a **public** repository is gated by GitHub Actions; a
**private** repository is gated by Trust CI, the self-hosted GitHub App
``adaptive-trust-ci`` whose code lives in ``trust-ci/``.

Visibility is read from GitHub: through the ``gh`` CLI when it is installed
(``gh api repos/<slug> --jq .private``, pinned to github.com so its token goes
nowhere new), otherwise through one unauthenticated HTTPS GET of
``https://api.github.com/repos/<slug>`` that carries no credentials at all. An
answer GitHub does not give positively is ``unknown`` and selects no gate: an
unauthenticated 404 cannot tell a private repository from a missing one, so the
caller has to name the visibility explicitly.

Every process and network call goes through an injected ``runner`` / ``fetch``
/ ``which`` so the decision logic is testable offline. Repository-relative
paths are POSIX strings and are joined component by component, so the module
behaves the same on Windows.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, NamedTuple, Sequence

PUBLIC = 'public'
PRIVATE = 'private'
UNKNOWN = 'unknown'
VISIBILITIES = (PUBLIC, PRIVATE, UNKNOWN)

GITHUB_ACTIONS = 'github-actions'
TRUST_CI = 'trust-ci'

WORKFLOW_PATH = '.github/workflows/getzilla-verify.yml'
TEMPLATE_PATH = '.getzilla/templates/ci/github-actions-verify.yml'
SOURCE_WORKFLOW_PATH = '.github/workflows/getzilla.yml'
ONBOARDING_RUNBOOK = 'engineering/runbooks/getzilla-trust-ci-onboarding.md'
TRUST_CI_ACCESS_URL = 'https://github.com/Dimkox/Getzilla/issues/new?template=trust-ci-access.yml'
CHECK_NAME = 'getzilla-verify'
BRANCH_PLACEHOLDER = '__GETZILLA_DEFAULT_BRANCH__'
FALLBACK_BRANCH = 'main'

GITHUB_API = 'https://api.github.com'
USER_AGENT = 'getzilla-ci-gate'
MAX_RESPONSE_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 20
HTTP_TIMEOUT_SECONDS = 10.0

_OWNER = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')
_REPOSITORY = re.compile(r'^[A-Za-z0-9._-]{1,100}$')
_BRANCH = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')
_REMOTE_PATTERNS = (
    # https://github.com/o/r(.git), http://, git://, optionally with user info
    re.compile(r'^(?:https?|git)://(?:[^@/\s]+@)?(?:www\.)?github\.com(?::\d+)?/(?P<path>[^?#\s]+)$', re.I),
    # ssh://git@github.com/o/r.git and ssh://git@ssh.github.com:443/o/r.git
    re.compile(r'^ssh://(?:[^@/\s]+@)?(?:ssh\.)?github\.com(?::\d+)?/(?P<path>[^?#\s]+)$', re.I),
    # scp-like git@github.com:o/r.git
    re.compile(r'^(?:[^@/:\s]+@)?github\.com:(?P<path>[^?#\s]+)$', re.I),
)


class CiGateError(RuntimeError):
    """A request the gate selector refuses; the message is safe to print."""


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class HttpResponse(NamedTuple):
    status: int  # 0 when no HTTP answer arrived (network error, timeout)
    body: bytes
    error: str = ''


class Visibility(NamedTuple):
    visibility: str
    source: str  # gh | https | explicit | none
    detail: str


Runner = Callable[[Sequence[str], 'Path | None'], CommandResult]
Fetcher = Callable[[str], HttpResponse]
Which = Callable[[str], 'str | None']


def run_command(args: Sequence[str], cwd: Path | None = None) -> CommandResult:
    """Run one command without a shell, prompts or unbounded waiting."""
    env = dict(os.environ)
    env.setdefault('GIT_TERMINAL_PROMPT', '0')
    env.setdefault('GH_PROMPT_DISABLED', '1')
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            list(args),
            cwd=None if cwd is None else str(cwd),
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(127, '', f'command not found: {args[0]}')
    except subprocess.TimeoutExpired:
        return CommandResult(124, '', f'timed out: {args[0]}')
    except OSError as exc:
        return CommandResult(126, '', f'{args[0]}: {exc}')
    return CommandResult(proc.returncode, proc.stdout or '', proc.stderr or '')


class _GitHubApiRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects (a renamed repository) only inside the GitHub REST API."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not str(newurl).startswith(GITHUB_API + '/'):
            raise urllib.error.HTTPError(newurl, code, 'redirect outside the GitHub REST API refused', headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_get(url: str) -> HttpResponse:
    """Unauthenticated GET of one GitHub REST API URL; no token is ever attached."""
    if not url.startswith(GITHUB_API + '/'):
        raise CiGateError('refusing a URL outside the GitHub REST API')
    request = urllib.request.Request(
        url,
        headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': USER_AGENT,
            'X-GitHub-Api-Version': '2022-11-28',
        },
        method='GET',
    )
    opener = urllib.request.build_opener(_GitHubApiRedirects)
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:  # nosec B310
            return HttpResponse(int(response.status), response.read(MAX_RESPONSE_BYTES + 1))
    except urllib.error.HTTPError as exc:
        return HttpResponse(int(exc.code), b'', str(exc.reason))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return HttpResponse(0, b'', str(getattr(exc, 'reason', exc)))


def is_valid_slug(slug: object) -> bool:
    if not isinstance(slug, str) or slug.count('/') != 1:
        return False
    owner, repository = slug.split('/')
    return bool(_OWNER.match(owner)) and bool(_REPOSITORY.match(repository)) and repository not in {'.', '..'}


def parse_github_remote(url: str) -> str | None:
    """Return ``owner/repo`` for a github.com https/ssh/scp remote URL, else None."""
    text = url.strip()
    for pattern in _REMOTE_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        path = match.group('path').strip('/')
        if path.lower().endswith('.git'):
            path = path[:-4]
        return path if is_valid_slug(path) else None
    return None


def repository_slug(root: Path | str, *, runner: Runner = run_command) -> str | None:
    """``owner/repo`` from ``git remote get-url origin``, or None when it is not GitHub."""
    result = runner(['git', 'remote', 'get-url', 'origin'], Path(root))
    if result.returncode != 0:
        return None
    lines = result.stdout.strip().splitlines()
    return parse_github_remote(lines[0]) if lines else None


def detect_visibility(
    slug: str | None,
    *,
    runner: Runner = run_command,
    fetch: Fetcher = https_get,
    which: Which = shutil.which,
) -> Visibility:
    """Ask GitHub whether ``slug`` is public or private; anything unconfirmed is unknown."""
    if not is_valid_slug(slug):
        return Visibility(UNKNOWN, 'none', 'origin is not a github.com repository')
    slug = str(slug)
    notes: list[str] = []
    gh = which('gh')
    if gh:
        result = runner([gh, 'api', '--hostname', 'github.com', f'repos/{slug}', '--jq', '.private'], None)
        answer = result.stdout.strip()
        if result.returncode == 0 and answer in {'true', 'false'}:
            visibility = PRIVATE if answer == 'true' else PUBLIC
            return Visibility(visibility, 'gh', f'gh api repos/{slug}: private={answer}')
        notes.append(f'gh api gave no answer (exit {result.returncode})')
    response = fetch(f'{GITHUB_API}/repos/{slug}')
    prefix = '; '.join(notes + [''])
    if response.status == 200:
        try:
            data = json.loads(response.body[:MAX_RESPONSE_BYTES].decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            data = None
        private = data.get('private') if isinstance(data, dict) else None
        if private is False:
            return Visibility(PUBLIC, 'https', f'{prefix}GET {GITHUB_API}/repos/{slug}: private=false')
        if private is True:
            return Visibility(PRIVATE, 'https', f'{prefix}GET {GITHUB_API}/repos/{slug}: private=true')
        return Visibility(UNKNOWN, 'https', f'{prefix}GitHub answered 200 without a boolean "private" field')
    if response.status == 404:
        return Visibility(
            UNKNOWN,
            'https',
            f'{prefix}GitHub answered 404 to an unauthenticated request: the repository is private or does not exist',
        )
    if response.status:
        return Visibility(UNKNOWN, 'https', f'{prefix}GitHub answered HTTP {response.status}')
    return Visibility(UNKNOWN, 'https', f'{prefix}no answer from GitHub: {response.error or "network error"}')


def select_gate(visibility: str) -> str | None:
    """``github-actions`` for public, ``trust-ci`` for private, None (no automatic choice) for unknown."""
    if visibility == PUBLIC:
        return GITHUB_ACTIONS
    if visibility == PRIVATE:
        return TRUST_CI
    if visibility == UNKNOWN:
        return None
    raise CiGateError(f'unsupported visibility: {visibility!r}')


def resolve_target_root(path: Path | str, *, runner: Runner = run_command) -> Path:
    """The Git work-tree root containing ``path`` (or ``path`` itself outside Git)."""
    candidate = Path(path)
    if not candidate.is_dir():
        raise CiGateError(f'target is not a directory: {candidate}')
    result = runner(['git', 'rev-parse', '--show-toplevel'], candidate)
    top = result.stdout.strip()
    if result.returncode == 0 and top:
        return Path(top).resolve()
    return candidate.resolve()


def _valid_branch(name: object) -> bool:
    if not isinstance(name, str) or not _BRANCH.match(name):
        return False
    return '..' not in name and '//' not in name and not name.endswith(('/', '.', '.lock'))


def default_branch(root: Path | str, *, runner: Runner = run_command) -> tuple[str, str]:
    """(branch, source): ``origin/HEAD`` when Git knows it, otherwise ``main``."""
    result = runner(['git', 'symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD'], Path(root))
    reference = result.stdout.strip()
    prefix = 'refs/remotes/origin/'
    if result.returncode == 0 and reference.startswith(prefix) and _valid_branch(reference[len(prefix):]):
        return reference[len(prefix):], 'origin/HEAD'
    return FALLBACK_BRANCH, 'fallback'


def render_workflow(template: bytes, branch: str) -> bytes:
    """The consumer workflow: template bytes with LF newlines and the push branch filled in."""
    if not _valid_branch(branch):
        raise CiGateError(f'unsupported default branch name: {branch!r}')
    text = template.replace(b'\r\n', b'\n').decode('utf-8')
    if text.count(BRANCH_PLACEHOLDER) != 1:
        raise CiGateError(f'{TEMPLATE_PATH} must contain {BRANCH_PLACEHOLDER} exactly once')
    return text.replace(BRANCH_PLACEHOLDER, branch).encode('utf-8')


def _join(root: Path, relative: str) -> Path:
    return root.joinpath(*relative.split('/'))


def _same_directory(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return False


def workflow_state(root: Path, content: bytes) -> tuple[str, str]:
    """(state, reason) for the consumer workflow: create | identical | conflict."""
    current = root
    for part in WORKFLOW_PATH.split('/')[:-1]:
        current = current / part
        if current.is_symlink() or (os.path.lexists(current) and not current.is_dir()):
            return 'conflict', f'{current.relative_to(root).as_posix()} exists and is not a plain directory'
    target = _join(root, WORKFLOW_PATH)
    if not os.path.lexists(target):
        return 'create', 'absent'
    if target.is_symlink() or not target.is_file():
        return 'conflict', f'{WORKFLOW_PATH} exists and is not a regular file'
    existing = target.read_bytes().replace(b'\r\n', b'\n')
    if existing == content:
        return 'identical', 'already matches the template'
    return 'conflict', f'{WORKFLOW_PATH} exists with different content; refusing to overwrite it'


def trust_ci_onboarding_steps(slug: str | None) -> list[str]:
    repository = slug or '<owner>/<repo>'
    owner = slug.split('/')[0] if slug else '<owner>'
    return [
        f'Nothing is written: {repository} is private, so its merge gate is Trust CI '
        '(the self-hosted GitHub App adaptive-trust-ci), not GitHub Actions.',
        'Trust CI is a paid service for private repositories (public repositories use GitHub Actions for free). '
        f'Request access for {owner}: {TRUST_CI_ACCESS_URL}',
        f'Once access is granted the operator adds an owner profile for {owner} to the deployed Trust CI policy '
        '(adaptive_trust_ci.customers add); repositories of any account without access are rejected before enqueue.',
        f'Install the adaptive-trust-ci GitHub App on {repository}.',
        'Open a small pull request and confirm the App-owned check adaptive-trust-ci/verified@<policy-sha12> '
        'on its exact head SHA.',
        'Only then bind branch protection to that check (adaptive-trust-ci branch-protect); protecting first '
        'can lock the repository.',
        f'Operator runbook: {ONBOARDING_RUNBOOK} in the Getzilla repository.',
    ]


def _actions_steps(state: str) -> list[str]:
    if state == 'source-repository':
        return [f'This is the Getzilla source repository; its own gate is {SOURCE_WORKFLOW_PATH}.']
    if state == 'conflict':
        return [f'Resolve the existing {WORKFLOW_PATH} by hand through a reviewed pull request, then rerun --plan.']
    return [
        f'Deliver {WORKFLOW_PATH} through a reviewed pull request.',
        f'After its first green run, require the {CHECK_NAME} check in the default branch protection '
        '(repository settings, an operator action).',
    ]


def plan_gate(
    target_root: Path | str,
    stack_root: Path | str,
    *,
    visibility: str | None = None,
    branch: str | None = None,
    runner: Runner = run_command,
    fetch: Fetcher = https_get,
    which: Which = shutil.which,
) -> dict[str, object]:
    """Read-only plan: detected visibility, selected gate and what a write would do."""
    root = Path(target_root)
    stack = Path(stack_root)
    slug = repository_slug(root, runner=runner)
    if visibility is None:
        detected = detect_visibility(slug, runner=runner, fetch=fetch, which=which)
    elif visibility in {PUBLIC, PRIVATE}:
        detected = Visibility(visibility, 'explicit', 'named by the caller')
    else:
        raise CiGateError(f'--visibility must be {PUBLIC} or {PRIVATE}, not {visibility!r}')
    gate = select_gate(detected.visibility)
    plan: dict[str, object] = {
        'schema_version': 1,
        'repository': slug,
        'visibility': detected.visibility,
        'visibility_source': detected.source,
        'visibility_detail': detected.detail,
        'gate': gate,
        'writes': [],
        'next_steps': [],
    }
    if gate == GITHUB_ACTIONS:
        if branch is None:
            branch_name, branch_source = default_branch(root, runner=runner)
        else:
            branch_name, branch_source = branch, 'explicit'
        template_file = _join(stack, TEMPLATE_PATH)
        if not template_file.is_file():
            raise CiGateError(f'missing workflow template: {TEMPLATE_PATH}')
        content = render_workflow(template_file.read_bytes(), branch_name)
        if _same_directory(root, stack) and _join(root, SOURCE_WORKFLOW_PATH).is_file():
            state, reason = 'source-repository', f'gated by its own {SOURCE_WORKFLOW_PATH}'
        else:
            state, reason = workflow_state(root, content)
        plan['writes'] = [{
            'path': WORKFLOW_PATH,
            'template': TEMPLATE_PATH,
            'state': state,
            'reason': reason,
            'push_branch': branch_name,
            'push_branch_source': branch_source,
            'sha256': hashlib.sha256(content).hexdigest(),
        }]
        plan['next_steps'] = _actions_steps(state)
    elif gate == TRUST_CI:
        plan['next_steps'] = trust_ci_onboarding_steps(slug)
    else:
        plan['next_steps'] = [
            'GitHub did not confirm the visibility, so no gate is chosen automatically; '
            'rerun with --visibility public or --visibility private.',
        ]
    return plan


def _create_exclusively(path: Path, content: bytes) -> bool:
    """Write a new file; False when something already occupies the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'xb') as handle:
            handle.write(content)
    except FileExistsError:
        return False
    return True


def apply_gate(
    target_root: Path | str,
    stack_root: Path | str,
    *,
    visibility: str | None = None,
    branch: str | None = None,
    runner: Runner = run_command,
    fetch: Fetcher = https_get,
    which: Which = shutil.which,
) -> dict[str, object]:
    """Plan, then perform the only write the plan allows; ``result`` says what happened."""
    root = Path(target_root)
    plan = plan_gate(root, stack_root, visibility=visibility, branch=branch, runner=runner, fetch=fetch, which=which)
    gate = plan['gate']
    if gate is None:
        plan['result'] = 'undetermined'
        return plan
    if gate == TRUST_CI:
        plan['result'] = 'nothing-to-write'
        return plan
    writes = plan['writes']
    entry = writes[0] if isinstance(writes, list) and len(writes) == 1 else {}
    state = entry.get('state')
    if state == 'identical':
        plan['result'] = 'unchanged'
    elif state == 'source-repository':
        plan['result'] = 'nothing-to-write'
    elif state == 'create':
        template = _join(Path(stack_root), TEMPLATE_PATH).read_bytes()
        content = render_workflow(template, str(entry['push_branch']))
        recheck, reason = workflow_state(root, content)
        if recheck == 'create' and _create_exclusively(_join(root, WORKFLOW_PATH), content):
            plan['result'] = 'written'
        elif recheck == 'identical':
            plan['result'] = 'unchanged'
        else:
            entry['state'], entry['reason'] = 'conflict', reason if recheck == 'conflict' else 'created concurrently'
            plan['result'] = 'refused'
    else:
        plan['result'] = 'refused'
    return plan
