# EU AI Act evidence (optional)

An opt-in layer for projects whose AI features reach people in the EU. It is off by default. Getzilla
produces engineering evidence for the obligations; it does not give legal advice, and the risk class is
always confirmed by a person.

## Turning it on

- **New installation.** When the system time zone or locale looks European, the installer asks once
  whether the project has users in the EU. The default answer is no. It never looks up your IP address
  or calls any service to decide.
- **Any time later.** Run `getzilla components add compliance:eu-ai-act` in the project. To turn it off,
  delete `.getzilla/compliance/eu-ai-act/`.
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
- `blocked`: anything else is outstanding. The author's machine makes this file, so it is evidence only. The independent decision is
Trust CI: add the command to its policy, and the signed exact-SHA attestation covers the bundle.

## Limits

- A marking can be stripped: a paraphrase, a screenshot or a re-encode removes most metadata and
  watermarks, and text is the weakest case. The check proves that the code calls the marking, not that
  the mark survives.
- Classification is a draft for a lawyer, not a legal conclusion. Edge cases need a legal reading.
- ISO/IEC 42001 certification does not give a presumption of conformity with the AI Act.
- The dates follow the AI Omnibus (Regulation (EU) 2026/1744, in force since 27 July 2026). Check them
  against the Official Journal and any later amendment before relying on them.
