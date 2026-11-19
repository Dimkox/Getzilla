# Incident-path classification repair — source observation

Read all 12 current issue bodies and comments from the controller snapshot. The exact #75 fixture first failed for both client-consent JSON files, two .qwen scratch files and the docs/test-evidence summary. Generated egg-info already classified correctly. The test's quarantine container assertion was corrected to its existing entries field.

Classify the two exact requirements paths without reading their contents. Classify test-evidence paths as evidence. Classify unowned .qwen files as user changes; unchanged manifest-owned files retain ownership priority. Keep other factory JSON unknown. Every incident row remains preserve, the quarantine entries remain empty and all fixture bytes remain unchanged.

Bounded command: `TMPDIR=<controller-runtime>/issues/ai-parent taskset -c 0-7 python3 -m unittest tests.test_installer.OwnershipPlanTests -q`. Observed 7 successful tests in 4.102s. No consumer migration or cleanup occurred. Full gate, review and delivery remain pending and are not run while the overall goal is paused.
