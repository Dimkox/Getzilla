# Risk vocabulary and language packs

The router reads the risk of a task from its prompt with a vocabulary in
`.getzilla/config/risk-terms/`:

- `en.json` is the **base**: term ids (`payment`, `login`, `refund`, `deploy`, ...), their category
  (`high` or `medium`) and English terms. Terms marked `neutral` (`api`, `n8n`, ...) are the same
  in every language.
- Every other `<lang>.json` is a **pack** that maps the same ids to terms in that language.
  `ru.json` is the first pack.

A trailing `*` matches a word prefix (`оплат*` matches `оплаты`, `оплату`, but not `переоплата`);
the words of a phrase must be adjacent. Terms without `*` match whole words only.

## Adding a language

The agent translates the base into a new pack:

```text
getzilla risk-terms scaffold --lang de --script LATIN --output de.json
# translate every entry of "hints" into "terms", remove "hints"
getzilla risk-terms check
```

`check` fails while any non-neutral base id has no translation, a term has `*` inside a word, or
the file name differs from `lang`. The pack belongs in `.getzilla/config/risk-terms/`, which is a
protected path: it changes risk policy, so it goes through a protected-path grant and review like
any other control-plane change.

## Prompts nobody can read

When most letters of a prompt are in a Unicode script that no pack covers (CJK, Arabic, ...), the
route is at least `medium` with the reason `PROMPT_LANGUAGE_NOT_COVERED:<SCRIPT>` and a hint to
scaffold a pack. A broken or missing vocabulary also gives `medium`, never `low`.

Only the script is detectable without a language model: a Latin-script prompt in a language that
has no pack is not flagged. The exact-head diff risk, which reads the changed files rather than
the prompt, covers that case.
