Historical candidate-only observation. Source 75ff49d / tree e1fc7e6 predates the repair below. This is not evidence for the repaired or merged candidate, current installation or production readiness.

# Candidate artifact smoke

Source identity:
75ff49d90546f2b89ad20cdc5f9e2a240f573914
e1fc7e6e69ab7f4a62701bded221d15c96583de4

Scratch: /home/pall/getzilla-candidate-artifact-31cxasfb (0700). CPU12-15; one worker.

Command: ["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", "/home/pall/getzilla-session/Getzilla", "/home/pall/getzilla-candidate-artifact-31cxasfb/source"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb
Exit: 0


Command: ["git", "checkout", "--quiet", "--detach", "75ff49d90546f2b89ad20cdc5f9e2a240f573914"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0


Command: ["git", "rev-parse", "HEAD", "HEAD^{tree}"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0
75ff49d90546f2b89ad20cdc5f9e2a240f573914
e1fc7e6e69ab7f4a62701bded221d15c96583de4


Command: ["python3", "scripts/package_stack.py", "--output", "/home/pall/getzilla-candidate-artifact-31cxasfb/first.zip"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0
/home/pall/getzilla-candidate-artifact-31cxasfb/first.zip
b32e88a7add6914f57125d333511de6931d7002476e0882e70c41e9b94c9bd99


Command: ["python3", "scripts/package_stack.py", "--output", "/home/pall/getzilla-candidate-artifact-31cxasfb/second.zip"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0
/home/pall/getzilla-candidate-artifact-31cxasfb/second.zip
b32e88a7add6914f57125d333511de6931d7002476e0882e70c41e9b94c9bd99


Archive SHA256: {"first.zip": "b32e88a7add6914f57125d333511de6931d7002476e0882e70c41e9b94c9bd99", "second.zip": "b32e88a7add6914f57125d333511de6931d7002476e0882e70c41e9b94c9bd99"}
Deterministic: True

Zip CRC result: None
Members: 5164
Manifest paths: ['getzilla/MANIFEST.sha256']

Command: ["python3", "scripts/verify_manifest.py"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla
Exit: 0
PASS manifest integrity


Command: ["python3", "scripts/install_into.py", "--plan", "--no-deps", "/home/pall/getzilla-candidate-artifact-31cxasfb/consumer"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla
Exit: 0
{"dependency_advice": [], "kept": [], "legacy_migration": [], "target_state": "absent", "version": 1}
entries: 629

Command: ["python3", "scripts/install_into.py", "--materialize-new", "/home/pall/getzilla-candidate-artifact-31cxasfb/consumer"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla
Exit: 0
{"dependency_advice": [{"advisory_only": true, "command": "https://git-scm.com/downloads", "id": "git", "profile": null, "required": true}, {"advisory_only": true, "command": "https://www.python.org/downloads/", "id": "python3", "profile": null, "required": true}], "kept": [], "legacy_migration": [], "target_state": "absent", "version": 1}
entries: 629

Command: ["python3", "scripts/getzilla_doctor.py"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/consumer
Exit: 0
PASS file:AGENTS.md: present
PASS file:.grok/config.toml: present
PASS file:.grok/hooks.json: present
PASS file:.agents/skills/getzilla-delivery/SKILL.md: present
PASS file:.getzilla/config/routing.json: present
PASS toml:.grok/config.toml: valid TOML
PASS json:.grok/hooks.json: valid JSON
PASS json:.qwen/settings.json: valid JSON
PASS json:.claude/settings.json: valid JSON
PASS json:.codex/hooks.json: valid JSON
PASS json:.gemini/settings.json: valid JSON
PASS json:.github/hooks/getzilla.json: valid JSON
PASS agent:ai_architect.toml: ai_architect
PASS agent:ai_implementer.toml: ai_implementer
PASS agent:architect.toml: architect
PASS agent:bitrix_architect.toml: bitrix_architect
PASS agent:bitrix_implementer.toml: bitrix_implementer
PASS agent:bitrix_reviewer.toml: bitrix_reviewer
PASS agent:code_reviewer.toml: code_reviewer
PASS agent:data_architect.toml: data_architect
PASS agent:data_implementer.toml: data_implementer
PASS agent:data_reviewer.toml: data_reviewer
PASS agent:docs_researcher.toml: docs_researcher
PASS agent:frontend_implementer.toml: frontend_implementer
PASS agent:general_implementer.toml: general_implementer
PASS agent:integration_architect.toml: integration_architect
PASS agent:integration_implementer.toml: integration_implementer
PASS agent:php_implementer.toml: php_implementer
PASS agent:release_reviewer.toml: release_reviewer
PASS agent:repo_explorer.toml: repo_explorer
PASS agent:security_reviewer.toml: security_reviewer
PASS agent:task_analyst.toml: task_analyst
PASS agent:test_reviewer.toml: test_reviewer
PASS skill:getzilla-delivery: valid frontmatter
PASS skill:ai-rag-change: valid frontmatter
PASS skill:api-event-change: valid frontmatter
PASS skill:bitrix-development: valid frontmatter
PASS skill:bugfix-workflow: valid frontmatter
PASS skill:data-change: valid frontmatter
PASS skill:enterprise-integration: valid frontmatter
PASS skill:feature-workflow: valid frontmatter
PASS skill:frontend-change: valid frontmatter
PASS skill:incident-response: valid frontmatter
PASS skill:legacy-modernization: valid frontmatter
PASS skill:release-readiness: valid frontmatter
PASS skill:security-sensitive-change: valid frontmatter
PASS skill:task-triage: valid frontmatter
PASS skill:verification-evidence: valid frontmatter
INFO unmanaged-skills: seo-landing
PASS repo-detection: generic; domains=[]; signals=['undetected-language', 'undetected-language:python=115', 'undetected-source-extension:.in=1', 'undetected-source-extension:.json=70', 'undetected-source-extension:.sh=1']
PASS adaptive-routing: Bitrix route selects specialized agents
INFO architecture-model: architecture documents are not present; skipped
INFO manifest: not generated yet; packaging creates it
PASS tool:python3: python3 3.12.3 (>= 3.10, built 3.12.3)
PASS tool:git: git 2.43.0 (>= 2.34, built 2.43.0)
PASS tool:grok: grok 1.0.43 (>= 1.0.0, built 1.0.5)
PASS tool:pwsh: pwsh 7.6.6 (>= 7.4, built 7.4.6)
PASS tool:gh: gh 2.86.0 (>= 2.40, built 2.86.0)
PASS tool:node: node 24.21.0 (>= 20.0, built 24.19.0)
PASS tool:npm: npm 11.19.0 (>= 9.0, built 11.17.0)
PASS tool:php: php 8.3.6 (>= 8.1, built 8.2)
INFO tool:composer: not installed; optional for php; required>=2.2 if used (built 2.7); Install fallback Composer 2.7 (or newer, built on 2.7): curl -sS https://getcomposer.org/installer | php && sudo mv composer.phar /usr/local/bin/composer
PASS tool:docker: docker 29.8.2 (>= 24.0, built 29.7.2)
PASS tool:syft: syft 1.51.0 (>= 1.0, built 1.51.0)
PASS tool:trivy: trivy 0.74.0 (>= 0.50, built 0.74.0)
INFO tool:cosign: not installed; optional for supply-chain; required>=2.0 if used (built ); Install fallback Cosign 2.4 (or newer, built on ): curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64 -o /tmp/cosign && sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
OFFER install fallback (or newer):
  composer: Install fallback Composer 2.7 (or newer, built on 2.7): curl -sS https://getcomposer.org/installer | php && sudo mv composer.phar /usr/local/bin/composer
  cosign: Install fallback Cosign 2.4 (or newer, built on ): curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64 -o /tmp/cosign && sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign


Command: ["python3", "scripts/install_into.py", "--materialize-new", "/home/pall/getzilla-candidate-artifact-31cxasfb/consumer"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla
Exit: 1
Traceback (most recent call last):
  File "/home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla/scripts/install_into.py", line 1659, in <module>
    main()
  File "/home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla/scripts/install_into.py", line 1640, in main
    result = _materialize_new(
             ^^^^^^^^^^^^^^^^^
  File "/home/pall/getzilla-candidate-artifact-31cxasfb/unpacked/getzilla/scripts/install_into.py", line 1481, in _materialize_new
    raise UnsafeInstallTarget("materialization requires an absent target")
UnsafeInstallTarget: materialization requires an absent target


Consumer sentinel preserved: True

Command: ["git", "diff", "--exit-code"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0


Command: ["git", "status", "--short"]
CWD: /home/pall/getzilla-candidate-artifact-31cxasfb/source
Exit: 0


Limitations: This qualifies the named candidate only. It is not a merged release attestation, full verifier receipt, native coding-agent task, unattended production runner, or production-target install. No services, vendor downloads, secrets, deployment, or publication. Exact merged SHA comparison remains required.

reviewed-tree-modified: no
