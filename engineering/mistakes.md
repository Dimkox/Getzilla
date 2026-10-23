# Recurring mistakes and countermeasures

This index contains repeated lessons, not a second incident log. Original wording and provenance remain in [dated incidents](incidents/README.md). A single occurrence stays an incident until recurrence is established.

## Resolve exact source identities

Resolve every commit through Git before using it in evidence or external actions; never extend an abbreviated SHA by hand.

Distinct recorded occurrences:

- [2026-08-26-root-337](incidents/2026-08-26-root-337.md)
- [2026-08-27-root-449](incidents/2026-08-27-root-449.md)

## Keep shell code separate from prose

Pass Markdown and literal patterns through structured arguments or body files. Backticks in double-quoted shell strings execute commands. Check the actual result before repeating an action.

Distinct recorded occurrences:

- [2026-09-01-root-574](incidents/2026-09-01-root-574.md)
- [2026-09-03-root-658](incidents/2026-09-03-root-658.md)
- [2026-09-03-root-663](incidents/2026-09-03-root-663.md)
- [2026-09-04-root-893](incidents/2026-09-04-root-893.md)
- [2026-09-05-root-897](incidents/2026-09-05-root-897.md)

For a new failure, record the date, concrete cause, consequence and countermeasure in a new incident. Link the actual PR when known; disclose unknown associations. Add a recurring lesson only when distinct incidents support it. Historical instructions remain observations of their dates, not current policy.
