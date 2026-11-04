# Skill intake and baseline asset custody

Status: source design; independent review and native qualification remain required.

Issue161 needs pre-install conflict/injection/provenance checks and a bounded trial without production
access. Existing toolchain pins, policy grants, canonical route ownership and lifecycle state already
provide separate parts of this contract. Syntax-only skill checks and an ambient versioned installer
do not prove the bytes that reach a project.

Use a closed, source-bound descriptive catalog and immutable content snapshots. Compare declared
constraints/capabilities and dependency pins before publication. Keep unknown semantics as `needs_review`.
Use the existing #150 owner/session/epoch and exact grants for external publication. A catalog entry,
model answer or imported approval phrase never grants a permission. Keep #156 trust/stop and #166 native
lifecycle boundaries separate; do not create another policy or identity store.

Run declarative interviews without dispatch adapters. Unsupported native requests refuse. For existing
baseline compatibility, ship fixed generated assets tied to full upstream archive/source pins, dependency
locks, exact generation commands and per-file hashes. BMAD/Spec Kit generation used an explicit disposable
Linux namespace with scratch output; ordinary consumers only validate/copy data. They do not need a Linux
sandbox dependency and never invoke ambient npx/specify. Preserve existing user directories.

Rejected alternatives: trusting arbitrary prose because pinned; another editable permission registry;
an untested native fallback; and requiring Bubblewrap for ordinary macOS/Windows installation. A parser-only
prototype would not cover actual installer effects. The selected path includes real installer, on-demand,
harness and baseline consumers while stating remaining semantic/native qualification limits.

Cost: fixed generated archives add source/release bytes and must be regenerated/reviewed with their input
pins. BMAD project-name rendering is a narrow deterministic transformation with a fresh manifest/digest.
Multi-file publication can leave partial state on interruption; it never claims a transactional rollback.
No source/pin/copy result establishes production access, runtime permission, legal or security approval.
