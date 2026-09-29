# lspipe — Named Pipe Lister

A Windows console tool that lists named pipes on the local machine or on a
remote machine over SMB.

Named pipes are an IPC (Inter-Process Communication) mechanism that lets two or
more processes exchange data, either on the same machine or across the network.
The named pipe namespace is backed by a file-system driver called `NPFS.SYS`
(Named Pipe File System).

`lspipe` provides two listing modes:

- **local** — enumerates pipes on the current machine using the native
  `NtQueryDirectoryFile` API against `\\.\pipe\`.
- **remote (SMB)** — enumerates pipes on a remote machine by connecting over
  SMB (TCP port 445) and performing an SMB2/SMB3 directory listing of the
  `IPC$` share.

All interaction is done through `std::cin` / `std::cout`. There are no command
line arguments, no flags, and no configuration files.

---

## Features

- List all named pipes on the local machine, including the number of active
  instances, the maximum instance count, and the server process ID (where it can
  be resolved).
- List named pipes on a remote machine over SMB.
- Support for both SMB3.1.1 (default) and SMB2 dialects.
- Support for NTLM authentication using a plaintext password or an NT hash.
- Optional pipe-name filtering.
- Clean, single-binary console application.

---

## Requirements

- Windows 7 or later (SMB2/SMB3 remote enumeration works best against Windows
  Vista / Server 2008 and later).
- A C++17-capable toolchain:
  - **MSVC** — Visual Studio 2019/2022 (MSVC toolset v142/v143), or
  - **MinGW-w64** (GCC), or
  - **CMake** 3.15+ (to drive either of the above).
- Windows SDK with the Windows headers and import libraries
  (`ws2_32.lib`, `bcrypt.lib`, `ole32.lib`).

---

## Build instructions

### Option A — Visual Studio (MSVC)

1. Open `lspipe.vcxproj` in Visual Studio 2019 or 2022.
2. Select the `x64` configuration.
3. Build the solution (**Build > Build Solution**).

The resulting executable is `x64\Debug\lspipe.exe` (or `x64\Release\lspipe.exe`).

> The project is configured as a **console application** (`Subsystem: Console`,
> `/utf-8`, C++17).

### Option B — CMake (MSVC or MinGW)

```powershell
# From the project directory
cmake -S . -B build
cmake --build build --config Release
```

To build with MinGW-w64 using CMake + Ninja:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Option C — MinGW-w64 (g++) directly

```powershell
g++ -std=c++17 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -O2 -o lspipe.exe `
  *.cpp -lws2_32 -lbcrypt -lole32
```

> If you prefer to be explicit, list the `.cpp` files from the `ClCompile`
> section of `lspipe.vcxproj` instead of using the `*.cpp` wildcard.

---

## Usage

Run the program from a console window:

```text
lspipe.exe
```

### 1. Local listing

```text
==============================================
          lspipe - Named Pipe Lister
==============================================
Select mode:
  1) local         - list pipes on this machine
  2) remote (SMB)  - list pipes on a remote machine over SMB
> 1
```

The program prints a table of pipes:

```text
Pipe Name                                    Instances   Max Instances   ProcessID
----------                                   ---------   -------------   ---------
InitShutdown                                        3              -1        656
lsass                                               4              -1        820
spoolss                                             3              -1       2624
...
[+] Final Pipelist
```

### 2. Remote listing over SMB

```text
> 2
Enter server name or IP address: 192.168.11.111
Enter username (empty for null session): user
Enter password (leave empty if using an NTLM hash): ********
Enter NTLM hash (optional, hexadecimal):
Enter domain (optional, default '.'): .
Use SMB2 instead of SMB3.1.1? (y/N): n
Enter pipe name filter (optional, default '*'): *
```

Field notes:

- **server name / IP** — required. Hostname, FQDN, or IPv4 address.
- **username** — leave empty for a null/anonymous session.
- **password** — leave empty when authenticating with an NT hash instead.
- **NTLM hash** — optional; when both a password and an NT hash are supplied,
  the NT hash takes precedence (as in the original logic).
- **domain** — optional; defaults to `.` (the local machine) when empty.
- **SMB dialect** — answer `y` to use SMB2, otherwise SMB3.1.1 is used.
- **filter** — optional pipe-name filter; defaults to `*` (list everything).

Example result:

```text
Pipe Name                                    Instances   Max Instances
----------                                   ---------   -------------
lsass                                               4              -1
epmapper                                            3              -1
spoolss                                             3              -1
...
[+] Final Pipelist
```

---

## Permissions and SMB notes

- **Local listing** requires the ability to open `\\.\pipe\` with
  `FILE_LIST_DIRECTORY` access. This is normally allowed for standard users.
  Resolving the `ProcessID` for a pipe may fail (showing `-1`) when the pipe is
  owned by a process running in a different session or at a higher integrity
  level (for example, services running as `SYSTEM`).
- **Remote listing** requires TCP port **445** to be reachable on the target
  host (the SMB port). Firewalls and network ACLs must allow it.
- SMB authentication uses the credentials you enter. If you supply a username
  and password/NT hash, the tool authenticates with NTLM. For the default
  SMB3.1.1 path, session traffic is encrypted and signed.
- Many modern Windows systems disable SMBv1 and may require SMB2/SMB3
  (supported here). Guest/null-session access is frequently disabled by default
  on hardened hosts, in which case valid credentials are required.
- **Responsible use only.** Enumerating named pipes on remote systems can reveal
  the presence of services and running processes. Only run this tool against
  systems you own or are explicitly authorized to test.
- Passwords are read through `std::cin` and may be echoed depending on the
  terminal; prefer an NT hash in non-interactive/CI scenarios.

---

## Project layout

- `main.cpp` — interactive entry point (`std::cin` / `std::cout`).
- `lspipe.cpp` / `lspipe.h` — local (`pipe_list`) and remote
  (`pipe_list_remote`) enumeration logic.
- `SMB2*`, `SMB3*` — SMB2/SMB3 protocol client implementation (negotiate,
  session setup, tree connect, directory query).
- `Bcrypt*` — Windows CNG crypto helpers (AES-CCM, HMAC, SHA-512).
- `ntlm.cpp` / `NtlmCalcCrypto.cpp` / `spnego.cpp` — NTLM/NTLMv2 and SPNEGO
  authentication.
- `SmbClient.*` / `windows_socket.*` — TCP transport over WinSock.
- `utils.*` — shared helpers and UTF-8/UTF-16 conversion for console I/O.
