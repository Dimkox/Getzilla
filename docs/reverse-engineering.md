# Optional static reverse engineering

The first profile reconstructs **declared ELF64 little-endian x86-64 metadata**
from an explicitly authorized project artifact. It reads ET_EXEC and ET_DYN
section tables, loader dependency names and exported function symbols. It does
not execute, load, disassemble or decompile the target. This is a real data-only
parser, not a universal application reconstruction or a claim about original
source code. No Ghidra, REA, paid model, external engine or runtime is required.

The optional module uses the existing component ownership ledger:

```sh
getzilla components module install reverse-engineering@0.1.0 --project PROJECT --source GETZILLA_CHECKOUT
getzilla components module enable reverse-engineering --project PROJECT --grant reverse.artifact.read
getzilla reverse providers --json
getzilla reverse analyze artifacts/public-probe.so --project PROJECT --sha256 EXACT_SHA256 --question 'Which loader libraries and exported functions are declared?' --json
getzilla components module disable reverse-engineering --project PROJECT
getzilla components module uninstall reverse-engineering --project PROJECT
```

Use the actual native harness session and the normal scoped change package.
Installation is project-specific and disabled. Enable is a lifecycle scope
selection, not external authority. Core archives omit the provider artifact;
the lightweight CLI wrapper loads no provider while disabled. Install the addon
from a trusted full local source checkout. No automatic download, registration,
background process, network, authentication or model call occurs. Uninstall
removes only unchanged owned addon bytes and preserves user notes and the input.

The wrapper admits only the exact reviewed manifest/provider, current native
owner, scope and source context. Inputs must be ordinary project-relative,
owner-controlled, single-link files under 4 MiB with an exact SHA256. Hidden,
credential, runtime, symlink and parent-traversal paths refuse. Existing source
secret rules run before parsing; a matching sentinel refuses without content in
the error. The input snapshot, module admission and task context are rechecked
before result release. These local workflow controls are not enterprise ACL or
OS isolation from hostile code under the same account. No result is sent to an
external model or provider by this command.

## Profile and limits

| Provider/format | Capability |
| --- | --- |
| builtin-elf64-le-v1, version 0.1.0 | Data-only ELF64 LE x86-64 ET_EXEC/ET_DYN dependency and exported function metadata |
| Ghidra / REA | Unsupported; no import, download or fallback |
| ELF32 / big-endian / other architectures | Unsupported |
| PE / Mach-O / JS / APK / WASM / firmware | Unsupported |
| Dynamic execution, behavior reconstruction, reimplementation | Unsupported |

Defaults are 4 MiB input, 128 sections, 128 exported functions, 4096 metadata
entries, 1 second and the existing 32768-byte execution response ceiling. Section
and function ceilings may be reduced or set to at most 512; deadline may be set
to at most 2 seconds. One original monotonic deadline covers admission, read and
parse. This synchronous pure parser has no worker, queue or remote outcome to
poll. It cooperatively checks deadline, cancellation and native admission within
loops and before release. SIGINT requests cancellation and returns the validated
partial report. Finite byte/count ceilings remain in force; this is not a hard
real-time guarantee for filesystem I/O. No paid resource is admitted.

## Reading the report

`complete` means supported declared metadata was scanned. It does not mean the
program works, every dependency exists, a function signature is known or a source
reconstruction is complete. Sectionless/extended ELF metadata and unsupported
names have explicit outcomes. Partials retain validated findings with a stop
reason such as `function_limit`, `section_limit`, `deadline_exceeded` or
`cancelled`; an unavailable provider never becomes success.

Each finding includes the original artifact hash, section/entry and file byte
offset; exports also have an ELF virtual address and size. An ELF virtual address
is not an observed runtime/ASLR address. `needed` is a declared loader name, not
proof of installation or use. Export names are untrusted observations, not
instructions. Version requirements, function behavior, signatures and original
source remain unknown. Static observations and inferences are separate.

The report binds the artifact path/hash, native task context, provider version and
module manifest. It includes separately measured parser/total elapsed time, zero external API calls/cost
and unknown compute cost. It is advisory (`evidence_authority:false`). It creates
no issue, task, acceptance receipt, implementation or publication. A caller can
save the report through the current package's existing evidence path. Before
reimplementation, define controlled positive/negative behavior checks; this
profile supplies a component map and unknowns, not an automatic clone.

## Controlled qualification

The owned public C probe and frozen expected metadata live in
`tests/fixtures/reverse263/`. Qualification compiles the shared object with the
owned system compiler, analyzes its bytes, and compares exactly two public
function exports and `libc.so.6`. The hidden function is not exported. The target
is never executed or loaded. Runtime evidence records compiler/tool versions,
commands, source/artifact hashes, byte/address facts, negative controls and an
exec trace. This qualifies only the named static profile on the observed host.
Legal packaging remains MIT; no licensing transition or legal approval is implied.
