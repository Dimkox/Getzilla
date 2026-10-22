# EU AI Act evidence (optional)

An opt-in layer for projects whose AI features reach people in the EU. It is off by default. Getzilla
produces engineering evidence for the obligations; it does not give legal advice, and the risk class is
always confirmed by a person.

## Turning it on

- **New installation.** When the system time zone or locale looks European, the installer asks once
  whether the project has users in the EU. The default answer is no. It never looks up your IP address
  or calls any service to decide.
- **Any time later.** Run `getzilla components add compliance:eu-ai-act` in the project. To turn it off,
  remove `eu-ai-act` from `.getzilla/config/compliance.json`. A CI audit requires committed opt-in and
  fails when this layer is disabled. On-demand installation supplies the audit and scaffold scripts
  and the adapter templates. Lean project installs omit those files. Before opt-in, the installed
  `getzilla compliance scaffold` command gives the component-install command and writes no adapter.
- **Without asking.** Set `GETZILLA_EU_AI_ACT=1` (or `0`) for the installer.

## How it works

1. **Register.** The project lists its AI systems in `.getzilla/config/ai-systems.json` (see
   `.getzilla/templates/ai-systems.example.json`). Each entry has:
   - a purpose and the code paths it owns;
   - a class (`prohibited`, `high-risk`, `limited`, `minimal`) and a `confirmation` (`by`, `role`, `date`);
   - a `role`: `provider`, `deployer` or both;
   - for a high-risk system, an `annex`: `III` (use cases) or `I` (products under EU product law);
   - optionally `placed_on_market` (`YYYY-MM-DD`), `generates_content`, `publishes_content` and `exemptions`.

   The file is in the control plane: an agent cannot write it without an exact grant.
2. **Draft class.** From the purpose Getzilla proposes a class. Credit scoring, recruitment, education
   assessment, biometrics and essential services are proposed as high-risk (Annex III). Assistants and
   content generation are proposed as limited (Art. 50). Social scoring, manipulation, and non-consensual
   intimate imagery or CSAM (a prohibition from 2 December 2026) are proposed as prohibited (Art. 5). The
   proposal never decides. A confirmed class below the draft needs `downgrade_reason`.
3. **Decision.** `verify` runs the `eu-ai-act` check and reports one of three decisions:
   - **REVIEW**: a person has to decide, and the agent cannot. The codes are:
     - `AI_SYSTEM_UNREGISTERED`: changed code calls an AI provider (the same detection as cost guard),
       and no system owns that path;
     - `AI_CLASS_UNCONFIRMED`: a system has no class or no confirmation;
     - `AI_CLASS_BELOW_DRAFT`: the confirmed class is below the draft and has no `downgrade_reason`;
     - `AI_ROLE_UNDECLARED`: no role is declared, so the obligations of both roles are checked;
     - `AI_ANNEX_UNDECLARED`: a high-risk system has no annex, so the earlier Annex III dates apply;
     - `AI_EXEMPTION_UNCONFIRMED`: an exemption has no basis or no confirmation, or the obligation has no
       exemption.
     - `MATRIX_STALE`: matrix source review metadata is missing, invalid, in the future or over 180 days old.
   - **BLOCK**: `AI_PROHIBITED_PRACTICE`, or `OBLIGATION_UNMET` for an obligation that is in force and has no
     evidence.
   - **PASS**: nothing above.

   In `pr` and `release` mode REVIEW and BLOCK both fail the check, and the summary starts with the
   decision. In `fast` mode the check passes with a warning. An obligation that is not yet in force and
   has no evidence is listed as upcoming with its date; it does not block.
4. **Evidence.** The obligation matrix (`.getzilla/compliance/eu-ai-act/obligations.json`) maps each
   article to a role, a date and a check:

   | Obligation | Applies to | Role | From | Evidence |
   |---|---|---|---|---|
   | Art. 5 | all | both | in force | class confirmed by a person, not prohibited |
   | Art. 50(1) disclosure | limited, high-risk | provider | 2 Aug 2026 | `disclosure_symbol` appears in the system code and in a test |
   | Art. 50(2) marking | limited, high-risk that generate content | provider | 2 Aug 2026; 2 Dec 2026 for systems placed on the market before 2 Aug 2026 | `marking_symbol` (for example the function that attaches C2PA Content Credentials) in code and a test |
   | Art. 50(4) deep fakes, public-interest text | limited, high-risk with `publishes_content` | deployer | 2 Aug 2026 | `publication_disclosure_symbol` in code and a test |
   | Art. 9 risk management | high-risk | provider | Annex III: 2 Dec 2027; Annex I: 2 Aug 2028 | committed `risk_register` JSON; every risk has a mitigation, an owner and a review date within 365 days |
   | Art. 11 technical documentation | high-risk | provider | as Art. 9 | the release audit bundle |
   | Art. 12 logs, Art. 14 oversight | high-risk | both | as Art. 9 | `logging_symbol`, `oversight_symbol` in code and a test |
   | Art. 15 accuracy, robustness, security | high-risk | provider | as Art. 9 | the verification run itself |

5. **Exemptions.** Art. 50 has exemptions. For example, the Art. 50(2) marking does not apply to an
   assistive function for standard editing, or to output that does not substantially alter the input.
   A system records an exemption as `{"obligation": "AIA-50-2", "basis": "...", "confirmation": {...}}`.
   Until a person confirms it, the obligation is still checked. Art. 5 and the high-risk obligations take
   no exemption here.

## Release decision

`python3 scripts/getzilla_audit_bundle.py --base <previous tag>` writes
`.getzilla/runtime/audit/audit-<commit>.json` with a SHA-256 sidecar. The file holds the matrix, the
register, every receipt bound to the exact tree, and `release_decision` with its reasons:
- `eligible`: nothing is outstanding;
- `review`: only a person's decision is outstanding;
- `blocked`: anything else is outstanding. A passing local verification receipt is required even when
  signed CI execution evidence is supplied. The author's machine produces the bundle. A CI signature
  can prove audit execution on the named source; it does not sign the regenerated bundle bytes.

## Matrix review

The matrix keeps `reviewed` and `sources`. Day 180 passes; day 181 gives `MATRIX_STALE` REVIEW.
The check also applies to an empty registry. Old matrices still parse, but missing review metadata
now needs review. The shipped `review_method` records an automated source check, not a human legal
review. Arrange a human review and record its actual reviewer, scope and date in the project's
evidence before treating it as human approval. Do not replace a review with a date edit. The 180-day
interval is a project rule. Engineering evidence, not legal advice.

The dates follow [Article 113](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113) and
[Regulation (EU) 2026/1744](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744),
in force from 27 July 2026. Annex III applies from 2 December 2027 and Annex I from 2 August 2028.
[Article 50](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50) generally applies from
2 August 2026; the stated transition for older synthetic systems ends on 2 December 2026.
Check against the official text and later amendments.

## Risk record

The original `risk`, `mitigation`, `owner` and `reviewed` fields remain valid. Optional `likelihood`
and `severity` must be integers 1–5; booleans are invalid. Optional `residual` is `low`, `medium` or
`high`. High residual risk requires `accepted_by: {by, role, date}`. This declaration does not
authenticate a person. Optional `next_review` must be a valid date that has not passed when the
obligation applies. Invalid applicable evidence gives `OBLIGATION_UNMET`. The example under
`.getzilla/templates/eu-ai-act/risk-register.example.json` is fictional. Replace all evidence and
confirmations. Scores and review intervals are project rules, not statutory thresholds. See
[Article 9](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-9).
Engineering evidence, not legal advice. Check against the official text.

## Transparency adapters

Run `getzilla compliance scaffold --system support-assistant --lang python`, or choose `typescript`
for Node. The first system glob must have a literal directory prefix and match the generated
filename. File-only paths, ambiguous prefixes, traversal, links and overwrites fail. The command
prints registry hints and leaves the registry unchanged. Python uses `mark_generated_content` and
`label_published_content`; TypeScript uses `markGeneratedContent` and `labelPublishedContent`.
Use `AI_DISCLOSURE` at the point of interaction.

Automatic scaffolding requires descriptor-relative file creation. It refuses before any write on
Windows, whose current helpers use paths and cannot prevent a parent-directory swap. On Windows,
copy the installed template manually from `.getzilla/templates/eu-ai-act/transparency/python/` or
`typescript/`, then add the language-specific registry hints. Both adapters remain usable.

Both adapters return original content and caller-approved public provenance labels. They do not
read model names or secrets from the environment. Returning this metadata alone does not embed
marking. If configured, `c2patool` has 30 seconds to mark a private copy and return separate marked
bytes. Missing tooling, errors and timeouts leave the input unchanged and set `c2pa_error`.
The Node adapter sends SIGKILL at timeout so a child that ignores SIGTERM cannot keep it waiting.
Configure a trusted C2PA signing identity separately. Test the actual publication path and verify
the output credentials before claiming embedded marking. Engineering evidence, not legal advice.
Check Article 50 against the official text.

## Independent verification

An EU-enabled CI profile can run `python3 scripts/getzilla_audit_bundle.py --ci-check`. Supply
`--base <exact SHA>` or the runner-owned `TRUST_CI_BASE_SHA`. No shell placeholder is expanded.
This mode binds `compliance.json`, the obligations matrix, `ai-systems.json`, `diff-risk-rules.json`
and `cost-providers.json` to committed bytes. Only the registry may be absent, and then it must be
absent in both Git and the working directory. It also compares committed and present executable
inputs, including hidden deletions. The evaluator receives explicit committed inputs for `--root`;
installed module defaults and provider caches cannot replace them. Git reads use a sanitized
environment with replacement objects disabled. One commit, base and UTC date govern evaluation;
optional ISO mapping and VERSION also come from that commit. It evaluates release
obligations, emits stdout only, and returns nonzero for REVIEW or BLOCK. It creates no receipt,
audit file or release-ready claim. Normal bundle generation keeps its local verification receipt
requirement. Engineering evidence, not legal advice.

CI opt-in comes from the captured committed config. A null or skipped EU report cannot pass CI.
Normal bundles retain the verifier's global/system ignore behavior for untracked files. That
bounded inventory pins the audited Git directory and work tree; ignores cannot admit uncommitted
decision inputs. The receipt format stays unchanged.

To add execution evidence to a normal bundle, supply `--attestation <envelope.json> --public-key
<public.pem> --attestation-verifier </trusted/install/bin/adaptive-trust-ci>` and a base. Use
`--repository owner/name` when the project has no GitHub origin. The public key and executable are
operator trust inputs. The executable must be outside the audited project; it runs offline with
fixed argv, a safe working directory, a minimal environment, a 30-second timeout and a 1 MiB output
limit. A valid signature must identify the same repository, base and commit. The job must have
passed and contain a passed audit command with integer exit code 0. The accepted form is
`[python3, scripts/getzilla_audit_bundle.py, --ci-check]` (also `python` or `python3.12`), optionally
followed by `--base` and the exact base SHA. Help, wrappers, extra root arguments and substrings
cannot qualify. Successful verification sets `authority: trust-ci-attested`; the signature covers
CI execution, not newly generated bundle bytes. Neither result grants merge or production authority.

The new v2 signed envelope adds optional `argv` and requires payload `schema_version: 2`.
V2 requires both `spec_digest` (nullable) and `criterion_coverage`, matching the current producer's metadata.
The v1 schema remains byte-identical. Legacy envelopes remain cryptographically valid but cannot
qualify EU execution, even if an unchecked dictionary adds argv. Old closed-schema validators and
verifiers reject v2; upgrade consumers before enabling the separate Trust CI producer and opt-in policy successor.
Never place secrets in signed argv. No deployed policy changes are included in this source change.
Keep full registries and bundles private until their contents are approved for sharing.

## ISO/IEC 42001

`compliance.iso42001` contains a project-authored clause-level map with `gating: false`. Missing or
malformed map files produce `null` and never change a decision. No paid standard text is copied.
The map is an aid, not certification or a presumption of AI Act conformity. Engineering evidence,
not legal advice. Check clauses A.2–A.10 against the official ISO/IEC 42001:2023 text.

## Limits

- A marking can be stripped: a paraphrase, a screenshot or a re-encode removes most metadata and
  watermarks, and text is the weakest case. The current symbol check searches code and test text.
  It does not prove that the function ran, that marking was embedded, or that the mark survives.
- Classification is a draft for a lawyer, not a legal conclusion. Edge cases need a legal reading.
- ISO/IEC 42001 certification does not give a presumption of conformity with the AI Act.
- `AIA-15` refers to generic verification. It does not establish model accuracy, robustness, tenant
  filtering, PII handling or deletion coverage. Record model/prompt versions, evaluation identities,
  quality, latency, cost and lifecycle evidence separately. The fictional risk example is not proof.
- The bundle supports [Article 11](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-11)
  evidence. It is not complete Annex IV documentation or a legal conformity assessment.
- The dates follow the AI Omnibus (Regulation (EU) 2026/1744, in force since 27 July 2026). Check them
  against the Official Journal and any later amendment before relying on them.
