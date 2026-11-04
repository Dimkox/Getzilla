# Test dependencies changed the offline release inventory

The architecture audit added the missing `jsonschema` test dependency to the
Factory development group. Its locked test environment then passed the affected
CLI tests, but the real isolated Actions run rejected the committed offline wheel
inventory. The audit had checked the dependency group and runtime requirements
without checking the offline builder's use of the whole lock.

The builder selected every locked package, including development-only nodes.
Updating only the lock hash would leave a different implicit runtime payload;
adding all new wheels would ship test dependencies. The repair derives the
runtime closure and requested transitive extras for the existing Linux CPython
3.12 profile. All 20 previous runtime wheel records remain unchanged.

Regression controls cover development groups, unrequested extras, inactive
platform edges, unresolved nodes and markers, and the interpreter contract.
An independent preliminary review found the inherited missing interpreter check;
the paired consumer controls now reject incompatible or unsupported contracts.
Unknown lock forms fail explicitly. This bounded builder does not claim to be a
general dependency resolver.

For future lock changes, validate both the test environment and the exact offline
runtime inventory. Local targeted controls do not replace the next exact-source
Actions run. The associated Factory audit failures remain tracked in #315 and
#320 until their acceptance evidence is complete.
