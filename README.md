# Docker Memory Analyzer User Guide

Docker Memory Analyzer is a Volatility 3 plugin for analyzing Docker-related traces, containers and tasks, mounts, networks, privileges, and open files in Linux memory images. It exposes a single public entry point, `linux.docker.Docker`, from which exactly one of the seven analyses below must be selected per invocation.

## 1. Analyses

| Question | Option | Main results |
|---|---|---|
| Are Docker or container traces present? | `--detector` | Runtime, mount, and network traces with collection status |
| Which containers are observable? | `--ps` | Container ID, representative process, start time, UID, and capabilities |
| Which paths are mounted in a container? | `--inspect-mounts` | Container paths, candidate host paths, filesystem types, and access modes |
| Which sockets, interfaces, and relationships are present? | `--inspect-networks` | Sockets, container relationships, interfaces, conntrack entries, and diagnostics |
| Which privileges and security settings apply to each task? | `--inspect-caps` | UIDs, capability sets, user namespaces, seccomp, and no-new-privileges |
| Does container task membership agree with shim ancestry? | `--container-tasks` | PIDs/TIDs, namespace PIDs, cgroup membership, shim ancestry, and conflicts |
| Which files are open in a container? | `--inspect-files` | File descriptors, file paths, candidate host paths, link state, and read status |

Analysis selectors cannot be combined. A secondary option is accepted only when it applies to the selected analysis.

## 2. Support Policy and Validated Scope

| Item | Policy or validated scope |
|---|---|
| Package-declared minimum Python version | Python 3.8 or later |
| Static target in this repository | Python 3.8 (`ruff.toml`) |
| Runtime version currently validated | Python 3.10.5 |
| Volatility 3 requirement | `volatility3>=2.28.0` |
| Volatility 3 version currently validated | Volatility 3 2.28.0 |
| Full-feature target | Linux x86-64 memory images with an exactly matching kernel ISF |
| cgroup support | Both v1 and v2 read paths, limited by the structures available in the image and symbols |

Python 3.8 is the minimum version declared by Volatility 3 2.28.0 and the static target of this repository. Runtime validation in a fresh Python 3.8 environment has not yet been completed. Versions newer than Volatility 3 2.28.0 may be installed under `requirements.txt`, but compatibility with future versions is not implied.

Full collection for `--inspect-networks`, `--inspect-caps`, and `--container-tasks` assumes Intel64 kernel structures. On other architectures or unsupported kernel layouts, all or part of an analysis may finish with an explicit unsupported or partial status.

## 3. Installation

### Windows PowerShell

```powershell
git clone https://github.com/KKudroK/docker-memory-analyzer.git
Set-Location docker-memory-analyzer

py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\vol.exe -p . linux.docker.Docker --help
```

### Linux or macOS

```bash
git clone https://github.com/KKudroK/docker-memory-analyzer.git
cd docker-memory-analyzer

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
vol -p . linux.docker.Docker --help
```

The help output should list all seven analysis selectors:

```text
--detector
--ps
--inspect-mounts
--inspect-networks
--inspect-caps
--container-tasks
--inspect-files
```

## 4. Memory Image and Kernel Symbols

Analysis requires a Linux memory image and a Volatility 3 ISF that exactly matches the kernel build and architecture of that image. Docker-specific symbols are not required.

```text
analysis-data/
├── memory.lime
└── symbols/
    └── linux/
        └── matching-kernel.json.xz
```

Pass the parent of the `linux` directory to `-s`. Verify the kernel banner and the basic process list before running this plugin:

```bash
vol --offline -f /path/to/memory.lime banners.Banners
vol --offline -s /path/to/symbols -f /path/to/memory.lime linux.pslist.PsList
```

A successful `linux.pslist.PsList` run shows that Volatility can read the base kernel layer and symbols. It does not prove that every Docker-specific field can be recovered. Review partial, unsupported, and diagnostic results from each analysis separately.

### ISF and BTF Compatibility

The recommended path is to obtain a debug-enabled `vmlinux` that matches the image and generate an ISF with the official Linux mode of `dwarf2json`:

```bash
dwarf2json linux --elf /path/to/vmlinux > /path/to/symbols/linux/matching-kernel.json
```

Third-party converters may also generate an ISF from BTF metadata. Producing a file, or loading it through a locally modified symbol loader, is not sufficient to claim official compatibility. Treat it as a reproducible Volatility 3 input only when all of the following conditions are met:

1. Unmodified Volatility 3 2.28.0 loads the ISF.
2. The ISF passes Volatility 3's official schema validation.
3. The banner reported by `banners.Banners` matches the ISF kernel build.
4. `linux.pslist.PsList` and the intended Docker analysis run in a clean environment.
5. Partial-read limitations caused by types, enumerations, or symbols missing from BTF are documented with the result.

When publishing validation based on a BTF-derived ISF, record the converter and version, source kernel package, conversion command, schema-validation result, and Volatility execution result. Do not describe a sample as officially schema-compatible if `jsonschema` validation was skipped or the result cannot be reproduced with stock Volatility.

## 5. Common Invocation

Place global options before the plugin name and analysis selectors and secondary options after it:

```bash
vol --offline -p /path/to/docker-memory-analyzer \
  -s /path/to/symbols -f /path/to/memory.lime \
  -o /path/to/results -r pretty \
  linux.docker.Docker ANALYSIS_OPTION
```

| Argument | Meaning |
|---|---|
| `--offline` | Use only locally available symbols |
| `-p` | Path to the root of this repository |
| `-s` | Symbol directory that contains `linux/` |
| `-f` | Linux memory image |
| `-o` | Existing directory in which the plugin writes evidence JSON files |
| `-r pretty` / `-r json` | Renderer used for the on-screen table |

In PowerShell, paths can be assigned once and reused:

```powershell
$VOL = '.\.venv\Scripts\vol.exe'
$PLUGIN = (Get-Location).Path
$DUMP = 'D:\dumps\memory.lime'
$SYMBOLS = 'D:\dumps\symbols'
$OUT = 'D:\dumps\results'
New-Item -ItemType Directory -Force -Path $OUT | Out-Null

& $VOL --offline -p $PLUGIN -s $SYMBOLS -f $DUMP -o $OUT -r pretty linux.docker.Docker --ps
```

## 6. Analysis Options

### 6.1 `--detector`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --detector
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --detector --limit 100000
```

`--limit` bounds the number of nodes visited during each kernel-object traversal. The default is `100000`, and the accepted range is `1..1000000`. It is not a container-count limit. The analysis checks runtime processes, Overlay mounts, and Docker-style network traces independently. It distinguishes `FOUND`, `NOT_OBSERVED`, and `UNKNOWN`, as well as `COMPLETE` and `PARTIAL`, so a failed read is not reported as a negative observation.

The main output contains the check name, observation, count, collection status, and supporting evidence. Detailed evidence is written to `detector_evidence.json`.

### 6.2 `--ps`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --ps
```

This analysis selects a representative task for each container and reports the container ID, command, host PID, process start time, effective UID, effective capabilities, `Configured Privileged`, and representative-selection evidence.

`Configured Privileged` is recovered from a cached Docker `hostconfig.json` found in memory. It is not inferred from capability masks, and `-` means unknown rather than `False`. The reported start time belongs to the representative process and must not be treated as the container creation time. Detailed evidence is written to `ps_evidence.json`.

### 6.3 `--inspect-mounts`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-mounts
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-mounts --pids 4283 4510
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-mounts --extended
```

| Secondary option | Meaning |
|---|---|
| `--pids PID [PID ...]` | Analyze the mount namespaces of the specified positive host PIDs |
| `--extended` | Add mount IDs and read-status fields |
| `--mounts-extended` | Compatibility alias for `--extended` |

The main output contains the PID, mount namespace, container ID, container path, candidate host paths, filesystem type, and read/write mode. If multiple host aliases are confirmed, all candidates are preserved. An unresolved path does not mean that the mount itself was absent. When diagnostics are produced, they are written to `containermounts-diagnostics.json`.

### 6.4 `--inspect-networks`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-networks
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-networks --view interfaces
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-networks --view diagnostics --dump-evidence
```

| Secondary option | Meaning |
|---|---|
| `--view sockets` | Default. Sockets recovered from file descriptors and their owning tasks |
| `--view containers` | Per-container task, socket, and network-namespace summary |
| `--view interfaces` | Interfaces, addresses, and MAC addresses within namespaces |
| `--view relations` | Container relationships supported by shared-socket or direct-connection evidence |
| `--view conntrack` | Recoverable conntrack entries and NAT information |
| `--view diagnostics` | Complete, partial, and unsupported status for each collector |
| `--container PREFIX [PREFIX ...]` | Restrict output to unique prefixes of container IDs observed by this analysis |
| `--dump-evidence` | Write evidence for the selected view to `network_evidence.json` |

Relationship output represents evidence observed between kernel objects. It does not recover packet contents or prove every historical connection. Closed file descriptors and overwritten memory can cause sockets to be absent.

### 6.5 `--inspect-caps`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-caps
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-caps --view analyst --leaders
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-caps --container abcdef123456
```

| Secondary option | Meaning |
|---|---|
| `--view raw` | Default. Raw per-task privilege and security observations |
| `--view analyst` | Evidence-based summary with a separate analyst JSON file |
| `--container PREFIX` | Restrict output to one unique 6-64 character hexadecimal container-ID prefix |
| `--leaders` | Collect process leaders only |
| `--unresolved` | Show tasks whose Docker membership could not be resolved |

`--container` and `--unresolved` cannot be combined. Capability values must be interpreted within their user-namespace scope, and capability sets alone do not prove that Docker `--privileged` was configured. `containercaps-audit.json` is always written; analyst view also writes `containercaps-analyst.json`.

### 6.6 `--container-tasks`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --container-tasks
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --container-tasks --details
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --container-tasks --triage
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --container-tasks --container abcdef123456
```

| Secondary option | Meaning |
|---|---|
| `--container PREFIX` | Restrict output to one unique 6-64 character hexadecimal container-ID prefix |
| `--details` | Show the full table, including PID/TID, PPID, namespace PID/TID, UID, capabilities, cgroups, and shim evidence |
| `--triage` | Show only unresolved or conflicting cgroup-membership and shim-ancestry results |

The default view summarizes the container, host PID/TID, task name, membership result, and recommended follow-up. `--triage` takes precedence over `--details`. A mismatch is an investigation lead, not proof of malicious activity. Full collection evidence and ancestry are written to `containertasks-audit.json` regardless of the selected view.

### 6.7 `--inspect-files`

```bash
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-files
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-files --view hosts
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-files --view details --full-id
vol --offline -p . -s SYMBOLS -f MEMORY -o RESULTS linux.docker.Docker --inspect-files --unlinked-only
```

| Secondary option | Meaning |
|---|---|
| `--view files` | Default. File descriptor, access mode, name state, and container path |
| `--view hosts` | Recovered candidate host paths and their status |
| `--view details` | Full process, inode, path, and read-status view |
| `--extended` | Alias for `--view details` |
| `--pids PID [PID ...]` | Analyze the specified TGIDs and file tables used by their threads |
| `--container PREFIX` | Restrict output to one unique 6-64 character hexadecimal container-ID prefix |
| `--unlinked-only` | Show only names whose current dentry state is `UNLINKED` |
| `--full-id` | Display full container IDs instead of shortened values |
| `--max-fds N` | Maximum file-descriptor slots per file table; default `65536`, range `1..1048576` |

Output always uses the three vertical columns `Record / Field / Value`; fields belonging to the same file descriptor share one record. `UNLINKED` describes the current name-link state and is not direct evidence of a deletion action. This analysis covers open file descriptors. It does not recover closed-descriptor history, file contents, files present only in VMAs, or every Overlay backing-layer object. When diagnostics are produced, they are written to `containerfiles-diagnostics.json`.

## 7. Screen Output and Evidence Files

The five analyses inherited from the 2021 plugin render long values as vertical blocks for readability. `--container-tasks` uses summary, details, or triage tables, and `--inspect-files` uses a vertical `Record / Field / Value` table. Automation should therefore prefer evidence JSON and documented field names over visual column placement.

| Analysis | Evidence file under `-o` |
|---|---|
| detector | `detector_evidence.json` |
| ps | `ps_evidence.json` |
| inspect-mounts | `containermounts-diagnostics.json` when diagnostics exist |
| inspect-networks | `network_evidence.json` when `--dump-evidence` is used |
| inspect-caps | `containercaps-audit.json`, plus `containercaps-analyst.json` in analyst view |
| container-tasks | `containertasks-audit.json` |
| inspect-files | `containerfiles-diagnostics.json` when diagnostics exist |

The existence of an evidence file does not prove complete collection. Always review its complete, partial, unsupported, and error states.

## 8. Changes from volatility-docker 2021

The original analytical goals are preserved, but collection, attribution, and output have been rebuilt for current kernel structures and the Volatility 3 2.28.0 API.

Saying that Volatility 3 2.28.0 now covers functionality needed by the 2021 plugin does **not** mean that the original `volatility-docker` source was merged into Volatility. It means that stock Volatility now provides official APIs and kernel-object support equivalent to foundations for which the 2021 plugin had to copy or replace `pslist.py`, `mount.py`, `ifconfig.py`, `file.py`, `pstree.py`, and Linux symbol extensions.

This version does not replace any Volatility 3 files. It calls the task traversal, namespace, mount, path, socket, and Linux symbol objects provided by stock 2.28.0, then adds Docker attribution, cross-container validation, partial-read preservation, and result rendering.

### 2021 Foundations Now Provided by Volatility 3 2.28.0

| Component bundled or modified in 2021 | Stock 2.28.0 foundation used now | Responsibility retained by this repository |
|---|---|---|
| Modified `pslist.py` and task helpers | `linux.pslist.PsList.list_tasks` and namespace-aware task/symbol objects | Combine cgroup, shim, and path evidence for container attribution and representative-task selection |
| `mount.py` and separate Linux mount extensions | `linux.mountinfo.MountInfo`, `mnt_namespace.get_mount_points()`, `LinuxUtilities.get_path_mnt()`, and `container_of()` | Collect mounts by container namespace, recover host aliases, support cgroup v1/v2, and preserve read diagnostics |
| Modified `ifconfig.py` and network symbol support | Official symbol/API foundations for current Linux network and socket objects | Attribute container FD sockets, interfaces, relationships, and conntrack entries and render view-specific output |
| Modified `pstree.py` | Parent relationships on official task objects and `PsList` enumeration | Perform bounded ancestry traversal and cross-check shim ancestry against cgroup membership |
| Modified `file.py` | Official VFS, file, and dentry kernel-object foundations | Analyze open FDs, candidate container/host paths, `UNLINKED` name state, and partial reads |
| Replaced internal Linux symbol extensions | Public 2.28.0 objects/APIs and `VersionRequirement` | Check required versions before execution without modifying stock framework files |

The final column does not imply that stock Volatility automatically produces Docker-specific results. Stock 2.28.0 provides the kernel-reading foundations; this repository supplies Docker grouping, interpretation, and output semantics.

### Mapping the 2021 Options to the Current Interface

| 2021 public option | Current equivalent | Change |
|---|---|---|
| `--detector` | `--detector` | The name is retained. Boolean-only detection is replaced by per-collector runtime, mount, and network observations, coverage, complete/partial status, and `detector_evidence.json`. |
| `--ps` | `--ps` | The running-container inventory remains, with cgroup, shim, and hostconfig evidence, representative-task selection, UID/capability fields, and provenance. |
| `--ps-extended` | Integrated into `--ps` | The separate extended selector was removed. `--ps` now displays the primary extended fields and writes full evidence to `ps_evidence.json`. |
| `--inspect-mounts` | `--inspect-mounts` | The purpose remains, but the implementation no longer relies on direct list traversal and the 2021 path whitelist. It uses current mount-namespace APIs, retains every decoded row, and separates container paths from host aliases. |
| `--inspect-mounts-extended` | `--inspect-mounts --extended` | The extended view became a secondary option. `--mounts-extended` is retained as a compatibility alias and adds mount IDs and read status. |
| `--inspect-networks` | `--inspect-networks` | This corresponds to the default socket view. Attribution preserves FD, namespace, and interface evidence rather than relying only on PIDs or a fixed network range. |
| `--inspect-networks-extended` | `--inspect-networks --view ...` | One wide extended table was replaced by `sockets`, `containers`, `interfaces`, `relations`, `conntrack`, and `diagnostics` views with explicit collection and output scope. |
| `--inspect-caps` | `--inspect-caps` | Collection now covers capability sets, UIDs, user namespaces, seccomp, and no-new-privileges rather than only an effective mask. It adds `--view raw|analyst`, `--leaders`, `--container`, and `--unresolved`. |
| Not present in 2021 | `--container-tasks` | New analysis for container process/thread details and agreement between cgroup membership and shim ancestry. |
| Not present in 2021 | `--inspect-files` | New analysis for open file descriptors, file paths, host aliases, and `UNLINKED` name state. |

Exactly one of these seven selectors must follow `linux.docker.Docker`. Secondary options such as `--extended`, `--view`, and `--container` are forwarded only when they are valid for the selected analysis.

| Area | 2021 version | Current version |
|---|---|---|
| Entry point | Features and extended views exposed as separate Boolean options | `linux.docker.Docker` selects exactly one of seven analyses and validates secondary options |
| Container attribution | Primarily `containerd-shim` names, parent/child relationships, and path patterns | Combines cgroup v1/v2 membership, runtime shim argv, namespaces, and path evidence while preserving conflicts and partial reads |
| Detector | Boolean results for Docker interfaces, veth, Overlay, and shims | Per-collector observations, complete/partial/unsupported status, and evidence JSON |
| Process inventory | Running containers with a limited process and privilege view | Representative-task evidence, start time, UID/capabilities, cached `Configured Privileged`, and provenance |
| Mounts | Direct mount-list traversal and path-whitelist filtering | Current list/RB-tree layouts, every recovered row, candidate host aliases, RO/RW state, and diagnostics |
| Networks | Primarily `/16` network grouping and container sets | Separate FD-socket, container, interface, relationship, conntrack, and diagnostics views |
| Capabilities | Primarily effective capabilities | Per-task capability sets, UID, user namespace, seccomp, no-new-privileges, and raw/analyst evidence |
| Tasks and shims | No independent detailed analysis | `--container-tasks` cross-checks processes/threads, shim ancestry, and cgroup membership |
| Open files | No independent container FD analysis | `--inspect-files` reports open FDs, container/host paths, unlinked names, and read status |
| Output | Different wide tables per option | Vertical output for long records, explicit task/file record shapes, and evidence JSON |
| Failure handling | Limited distinction between empty results and unobserved data | `COMPLETE`, `PARTIAL`, `UNSUPPORTED`, `UNKNOWN`, and diagnostics preserve collection limits |

### Files and Execution Flow

```text
vol CLI
└─ linux/docker.py
   ├─ verifies that exactly one of seven analyses is selected
   ├─ validates secondary options for that analysis
   └─ loads only the selected backend
      ├─ detector.py
      ├─ ps.py
      ├─ inspect_mount.py
      ├─ inspect_networks.py
      ├─ inspect-caps.py
      ├─ container_tasks.py
      └─ inspect_files.py
         ├─ versioned shared API in linux/docker_artifacts.py
         ├─ cgroup, namespace, mount, path, task, and file readers in linux/_artifacts/
         └─ stock Volatility 3 2.28.0 PsList, MountInfo, LinuxUtilities, and kernel objects
            ├─ on-screen TreeGrid result
            └─ evidence or diagnostics JSON under the -o directory
```

`linux/docker.py` is a dispatcher. It does not perform the analysis itself; it validates the selector and secondary-option combination and forwards the resulting configuration to the selected backend. Backends use the shared readers in `linux/docker_artifacts.py` and `linux/_artifacts/` to access stock Volatility objects. They return screen output as a Volatility `TreeGrid` and write detailed evidence or read failures to the JSON files below.

| File or directory | Current role and difference from the 2021 version |
|---|---|
| `linux/docker.py` | Single public entry point for seven analyses, option validation, and selected-backend execution |
| `detector.py` | Docker trace detection with independent collector status and evidence |
| `ps.py` | Container and representative-process summary based on cgroup and task evidence |
| `inspect_mount.py` | Recovery of current mount layouts, host aliases, access modes, and diagnostics |
| `inspect_networks.py` | Socket, interface, relationship, conntrack, and diagnostics views |
| `inspect-caps.py` | Raw and analyst views of task privileges and security context |
| `container_tasks.py` | New analysis that combines container processes/threads, shim ancestry, and membership validation |
| `inspect_files.py` | New analysis of open file descriptors, paths, and name-link state |
| `linux/_artifacts/` | Shared low-level readers for cgroups, namespaces, mounts, paths, tasks, credentials, and files |
| `linux/docker_artifacts.py` | Versioned shared collection API used by the backends |
| `linux/_vertical.py` | Common helper that converts wide records into category/value blocks |

| Selector | Backend | Main file output |
|---|---|---|
| `--detector` | `detector.py` | `detector_evidence.json` |
| `--ps` | `ps.py` | `ps_evidence.json` |
| `--inspect-mounts` | `inspect_mount.py` | `containermounts-diagnostics.json` when diagnostics exist |
| `--inspect-networks` | `inspect_networks.py` | `network_evidence.json` when `--dump-evidence` is used |
| `--inspect-caps` | `inspect-caps.py` | `containercaps-audit.json`, plus `containercaps-analyst.json` in analyst view |
| `--container-tasks` | `container_tasks.py` | `containertasks-audit.json` |
| `--inspect-files` | `inspect_files.py` | `containerfiles-diagnostics.json` when diagnostics exist |
