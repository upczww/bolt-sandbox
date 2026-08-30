# Native API Coverage Inventory

This inventory prevents phrases such as “all relevant APIs” from hiding an
untested entry point. Names identify required behavior families; imported
BuildXL/Detours implementation may hook a lower layer that covers several named
wrappers. A release still needs evidence that every row reaches the expected
decision on x64 and x86. APIs unavailable on a supported Windows version must
produce a recorded `not_present` capability result, not a skipped test.

## Filesystem

| API/operation family | Representative entry points | Catalog evidence |
| --- | --- | --- |
| Open/create | `CreateFileW/A`, `CreateDirectoryW/A/ExW/ExA`, `NtCreateFile`, `NtOpenFile`, root-handle relative opens | FS-001..009, FS-011..020, FS-051..052 |
| Read/write sync | `ReadFile`, `WriteFile`, `NtReadFile`, `NtWriteFile` | FS-001..009, FS-051, SEM-004 |
| Read/write async | `ReadFileEx`, `WriteFileEx`, overlapped `ReadFile`/`WriteFile`, IOCP/thread-pool completion | FS-057..059 |
| Copy | `CopyFileW/A`, `CopyFileExW/A`, `CopyFile2` | FS-039..040, FS-051 |
| Move/rename | `MoveFileW/A`, `MoveFileExW/A`, `SetFileInformationByHandle`, `NtSetInformationFile` rename classes | FS-029..035, FS-051 |
| Replace | `ReplaceFileW/A`, rename-exchange/replace information classes | FS-032..033 |
| Delete/disposition | `DeleteFileW/A`, `RemoveDirectoryW/A`, delete-on-close, Win32/NT disposition classes | FS-004..006, FS-034..035, FS-047 |
| Truncate | create dispositions, `SetEndOfFile`, allocation/end-of-file information classes | FS-004, FS-036 |
| Enumeration | `FindFirstFile*`, `FindNextFile*`, `NtQueryDirectoryFile`, `NtQueryDirectoryFileEx` | FS-002, FS-010, FS-042 |
| Metadata query | `GetFileAttributes*`, `GetFileInformationByHandle*`, `NtQueryInformationFile`, `NtQueryAttributesFile`, `NtQueryFullAttributesFile` | FS-010, FS-043 |
| Metadata mutation | `SetFileAttributes*`, time/security/compression/encryption operations, basic and short-name information classes | FS-044 |
| Hard link | `CreateHardLinkW/A`, link information classes | FS-026..027 |
| Symlink/reparse | `CreateSymbolicLinkW/A`, reparse-point controls, junction traversal | FS-021..025, FS-028, BYP-005 |
| Alternate/object identity | ADS, 8.3 name, file ID/object ID, final path/volume identity | FS-017..018, FS-054, FS-060, SEM-003 |
| Mapping/section | `CreateFileMappingW/A`, `NtCreateSection`, `MapViewOfFile*`, `NtMapViewOfSection`, flush/unmap | FS-037..038, FS-062 |
| Directory notification | `ReadDirectoryChangesW`, `NtNotifyChangeDirectoryFile`, `NtNotifyChangeDirectoryFileEx` | FS-061 |
| Shell operations | `SHFileOperationW/A`, `IFileOperation` copy/move/delete/rename | FS-041 |
| Handle capability | inherited handles, `DuplicateHandle`, delete/rename/truncate by handle | FS-030, FS-034..036, FS-045..046, BYP-007..008 |

Each family must include allowed, read-only/denied, ordinary OS failure,
alias/final-target, event, and side-effect assertions where the operation
supports those outcomes. `SEM-004` maintains the authoritative mapping from
access masks/dispositions/information classes to policy operation classes.

## Process creation and control

| API/operation family | Representative entry points | Catalog evidence |
| --- | --- | --- |
| Standard process creation | `CreateProcessW/A` and flag variants | PROC-001..009, PROC-025 |
| Token/user creation | `CreateProcessAsUserW/A`, `CreateProcessWithTokenW`, `CreateProcessWithLogonW` | PROC-026..027 |
| Shell/association activation | `ShellExecuteExW`, association and covered COM shell activation | PROC-020, PROC-028 |
| Native creation | `NtCreateUserProcess`, `RtlCreateUserProcess` | PROC-009, PROC-029 |
| Architecture selection | PE image inspection plus WOW64/process-machine queries | PROC-002, PROC-004..006, PROC-015, PROC-030 |
| External process/handle tampering | `OpenProcess`, `DuplicateHandle`, `WriteProcessMemory`, covered remote-thread APIs | SEC-011, BYP-008 |
| Job and mitigation control | Job assignment/breakaway/termination and process mitigation query/set | PROC-011..013, PROC-031..034, LIFE-003..008 |

## Network

| API/operation family | Representative entry points | Catalog evidence |
| --- | --- | --- |
| Socket connect | `connect`, `WSAConnect`, `ConnectEx` | NET-001, NET-003, NET-008..009, NET-013..014 |
| DNS synchronous | `getaddrinfo`, `GetAddrInfoW`, `DnsQuery_*` supported variants | NET-002, NET-005, NET-015..017 |
| DNS asynchronous | `GetAddrInfoEx*`, `DnsQueryEx`, cancellation/completion | NET-002, NET-005, NET-015..017, NET-023 |
| WinHTTP | session/connect/request/send/receive and redirect/proxy paths | NET-006, NET-018..020, NET-022 |
| WinInet | open/connect/request/send/read and redirect/proxy paths | NET-006, NET-018..020, NET-022 |
| UDP/custom/unsupported | socket send/connect, raw socket, QUIC/custom stacks | NET-004, NET-025 |
| Address/identity | IPv4, IPv6, mapped addresses, zones, IDN, CNAME, TTL binding | NET-012..017, NET-024, SEM-006..007 |
| Socket capability | inherited/preconnected/duplicated sockets and reuse races | NET-023, NET-027, BYP-007..008 |

## Registry

| API/operation family | Representative entry points | Catalog evidence |
| --- | --- | --- |
| Create/open | `NtCreateKey`, `NtOpenKey`, `NtOpenKeyEx` and Win32 `RegCreate/Open*` wrappers | REG-001..008, REG-015..016 |
| Query/enumerate | `NtQueryKey`, `NtQueryValueKey`, `NtEnumerateKey`, `NtEnumerateValueKey` | REG-001, REG-004, REG-015 |
| Set | `NtSetValueKey` and `RegSetValueEx*` | REG-002, REG-005, REG-015..016 |
| Delete | `NtDeleteKey`, `NtDeleteValueKey` and Win32 wrappers | REG-002..005, REG-015..016 |
| Rename | `NtRenameKey` and covered Win32 behavior | REG-003..005, REG-013, REG-015 |
| Identity/views/handles | predefined/root handles, symbolic links, WOW64 views, inherited/duplicated handles | REG-010..014, BYP-004, BYP-007..008 |
| Explicitly unsupported | transactional and remote registry operations | REG-017 |

## Coverage maintenance

- The machine-readable
  [`hooks-manifest.json`](../../native/hook/filesystem/hooks-manifest.json)
  must list every installed filesystem target symbol, module,
  architecture, minimum OS version, operation class, and catalog case IDs.
- CI compares that manifest with this inventory and fails on unmapped additions,
  removals, unavailable required symbols, or a hook without an allow/deny/error
  test vector.
- [`filesystem-evidence.json`](filesystem-evidence.json) records whether each
  `FS-001..064` case is covered, partial, or a gap and pins non-gap claims to
  source anchors. `scripts/audit-filesystem-evidence.ps1` validates the inventory
  during Windows builds; release validation adds `-RequireComplete` and fails
  while any partial or gap remains.
- API aliases covered solely through a lower-level hook still require an
  integration probe proving that the wrapper reaches the lower-level decision.
- `HOOK-009` verifies the runtime-installed set; static manifest coverage alone
  is insufficient.
