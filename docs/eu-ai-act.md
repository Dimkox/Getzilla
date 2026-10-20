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
   `.getzilla/templates/ai-systems.example.json`). Each entry has a purpose, the code paths it owns,
   a class (`prohibited`, `high-risk`, `limited`, `minimal`) and a `confirmation` (`by`, `role`, `date`).
   The file is in the control plane: an agent cannot write it without an exact grant.
2. **Draft class.** From the purpose Getzilla proposes a class. Credit scoring, recruitment, education
   assessment, biometrics and essential services are proposed as high-risk (Annex III). Assistants and
   content generation are proposed as limited (Art. 50). Social scoring and manipulation are proposed as
   prohibited (Art. 5). The proposal never decides. A confirmed class below the draft needs
   `downgrade_reason`.
3. **Gate.** `verify` runs the `eu-ai-act` check. In `pr` and `release` mode it fails on:
   - `AI_SYSTEM_UNREGISTERED`: changed code calls an AI provider (the same detection as cost guard),
     and no system owns that path;
   - `AI_CLASS_UNCONFIRMED`: a system has no class or no confirmation;
   - `AI_CLASS_BELOW_DRAFT`: the confirmed class is below the draft and has no `downgrade_reason`;
   - `AI_PROHIBITED_PRACTICE`: a system is classified prohibited;
   - `OBLIGATION_UNMET`: an obligation of the class has no evidence.
4. **Evidence.** The obligation matrix (`.getzilla/compliance/eu-ai-act/obligations.json`) maps each
   article to a check:

   | Obligation | Applies to | Evidence |
   |---|---|---|
   | Art. 5 | all | class confirmed by a person, not prohibited |
   | Art. 50(1) disclosure | limited, high-risk | `disclosure_symbol` appears in the system code and in a test |
   | Art. 50(2) marking | limited, high-risk that generate content | `marking_symbol` (for example the function that attaches C2PA Content Credentials) in code and a test |
   | Art. 9 risk management | high-risk | committed `risk_register` JSON; every risk has a mitigation, an owner and a review date within 365 days |
   | Art. 11 technical documentation | high-risk | the release audit bundle |
   | Art. 12 logs, Art. 14 oversight | high-risk | `logging_symbol`, `oversight_symbol` in code and a test |
   | Art. 15 accuracy, robustness, security | high-risk | the verification run itself |

## Release decision

`python3 scripts/getzilla_audit_bundle.py --base <previous tag>` writes
`.getzilla/runtime/audit/audit-<commit>.json` with a SHA-256 sidecar. The file holds the matrix, the
register, every receipt bound to the exact tree, and `release_decision` (`eligible` or `blocked` with
reasons). The author's machine makes this file, so it is evidence only. The independent decision is
Trust CI: add the command to its policy, and the signed exact-SHA attestation covers the bundle.

## Limits

- A marking can be stripped: a paraphrase, a screenshot or a re-encode removes most metadata and
  watermarks, and text is the weakest case. The check proves that the code calls the marking, not that
  the mark survives.
- Classification is a draft for a lawyer, not a legal conclusion. Edge cases need a legal reading.
- ISO/IEC 42001 certification does not give a presumption of conformity with the AI Act.
- Application dates in the matrix are informational. Check them against the Official Journal and any
  later amendment before relying on them.
