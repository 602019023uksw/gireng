# BPFDoor Malware Analysis Report

**Sample**: `fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73.elf.x86_64`
**Analysis type**: Static only (no execution)
**Date**: 2026-03-02

---

## 1. File Metadata

| Property | Value |
|---|---|
| SHA256 | `fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73` |
| MD5 | `0017f7b913ce66e4d80f7e78cf830a2b` |
| SHA1 | `f1bf775746a5c882b9ec003617b2a70cf5a5029` |
| Build ID | `1e3c06cce8dc23d9bf96c3a524404122bc281c71` |
| File size | 28,832 bytes |
| Type | ELF 64-bit LSB executable, x86-64 |
| Linking | Dynamically linked (`libc.so.6` only) |
| Stripped | **No** — full symbol table present (154 symbols) |
| Compiler | GCC 4.8.5 20150623 (Red Hat 4.8.5-4) |
| Min kernel | Linux 2.6.32 |
| Source file | `a.c` (single source file) |

---

## 2. Maliciousness Assessment: CRITICAL / CONFIRMED MALWARE

**Confidence**: 100% malicious. This is a fully functional BPFDoor implant — a passive network backdoor associated with Chinese state-sponsored threat actor Red Menshen (APT group). No ambiguity.

Key malice indicators:
- Raw socket with BPF filter for covert packet sniffing (no listening port visible to `netstat`/`ss`)
- Multi-protocol magic packet activation (TCP, UDP, ICMP)
- RC4-encrypted command authentication
- Reverse shell and bind shell capabilities
- iptables manipulation to punch firewall holes
- Process name masquerading via `prctl(PR_SET_NAME)` + argv overwrite
- Self-copy to `/dev/shm/` (tmpfs, never touches disk)
- PID file lock at `/var/run/haldrund.pid` to masquerade as legitimate daemon
- Timestamp manipulation via `utimes()`

---

## 3. Execution Flow

### 3.1 Initialization (`main` at 0x403e2e)

1. **Singleton check**: Calls `access("/var/run/haldrund.pid", F_OK)`. If the PID file exists, exits immediately (only one instance allowed).
2. **Root check**: Calls `getuid()`. If not root (UID 0), exits. Requires root to open raw sockets.
3. **`--init` mode**: If called with exactly 1 argument, runs `to_open(argv[0], "--init")` which copies itself to `/dev/shm/`, executes the copy, then deletes it from `/dev/shm/`. This is the initial deployment mechanism.
4. **Password setup**: Builds two passwords on the stack char-by-char (anti-strings evasion):
   - `justforfun` → stored at `cfg+0x208` (authentication password — grants shell)
   - `socket` → stored at `cfg+0x216` (second password — triggers different behavior)
5. **Process masquerading**: Randomly selects one of 10 fake process names and calls `set_proc_name()` to overwrite argv[0] and use `prctl(PR_SET_NAME, ...)`.
6. **Timestamp preservation**: `setup_time()` calls `utimes()` on the binary to preserve original timestamps.
7. **Daemonization**: Calls `daemon(0, 0)` to fork into background, then `chdir("/")`.
8. **Signal setup**: Installs signal handlers (`init_signal`), sets SIGCHLD handler to `sig_child`.
9. **PID file creation**: Creates `/var/run/haldrund.pid` with mode 0644.
10. **Enter packet loop**: Calls `packet_loop()` — the main sniffing loop.

### 3.2 Fake Process Names (randomly selected)

These are stored in `.rodata` and loaded into the name array in `main`:

1. `/sbin/udevd -d`
2. `/sbin/mingetty /dev/tty7`
3. `/usr/sbin/console-kit-daemon --no-daemon`
4. `hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event`
5. `dbus-daemon --system`
6. `hald-runner`
7. `pickup -l -t fifo -u`
8. `avahi-daemon: chroot helper`
9. `/sbin/auditd -n`
10. `/usr/lib/systemd/systemd-journald`

Additional masquerading string for child processes:
- `/usr/libexec/postfix/master` (used after activation)
- `qmgr -l -t fifo -u` (used in shell sessions)
- `kdmtmpflush` (in rodata)

### 3.3 BPF Packet Filter (raw socket sniffing)

The implant opens a raw socket with `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` and attaches a BPF filter that accepts **only** these packet types:

| Protocol | Match Criteria | Magic Value |
|---|---|---|
| **UDP** | Destination port | **29269** (0x7255) |
| **ICMP** | Type = Echo Request (8) | Payload inspected after header |
| **TCP** | First 2 bytes of TCP payload | **0x5293** (21139) |

Everything else is dropped by the BPF filter at the kernel level — extremely efficient and invisible to userspace tools. The raw socket does not bind to any port, so `netstat`/`ss` will **never** show a listening port.

### 3.4 Packet Processing (`packet_loop` at 0x402308)

When a matching packet arrives via `recvfrom()`:

1. Parses the IP header to determine protocol (TCP=6, UDP=17, ICMP=1).
2. For TCP: extracts IP header length, TCP header length, locates payload.
3. For UDP: skips to UDP payload at offset +8.
4. For ICMP: skips to ICMP payload at offset +8.
5. Extracts the command IP address (from packet's source IP, or from a field in the payload if present).
6. **Forks** a child process for each activation.
7. Child process:
   - Calls `fork()` again + `setsid()` to fully detach.
   - Overwrites argv[0] with `/usr/libexec/postfix/master`.
   - Uses `prctl(PR_SET_NAME, "/usr/libexec/postfix/master")`.
   - Initializes **two RC4 contexts** (`crypt_ctx` and `decrypt_ctx`) using the magic packet payload as the key.
8. Calls `logon()` to authenticate the operator.

### 3.5 Authentication (`logon` at 0x402292)

Compares the RC4-decrypted payload against two passwords:

| Password | Return Value | Action |
|---|---|---|
| `justforfun` | 0 | Connects back to the operator via `try_link()` → `shell()` (direct shell mode) |
| `socket` | 1 | Extracts IP+port from packet, calls `getshell()` (iptables redirect + bind shell) |
| anything else | 2 | Calls `mon()` — sends a UDP probe back to the operator (monitoring/ping mode) |

### 3.6 Shell Access Modes

#### Mode 1: Reverse Connect (`try_link` + `shell`)
- `try_link()`: Creates a TCP socket, connects back to the operator's IP on the port specified in the magic packet.
- `shell()`: Spawns `/bin/sh` via PTY (`ptym_open`/`ptys_open`), sets up STREAMS modules (`ptem`, `ldterm`, `ttcompat`), and relays I/O between the network socket and the shell using RC4-encrypted read/write (`cread`/`cwrite`).
- Process masquerades as `qmgr -l -t fifo -u`.

#### Mode 2: iptables Redirect + Bind Shell (`getshell`)
- Calls `b()` to bind a TCP listening socket on a port in range **42391–43390** (0xa597–0xa97e).
- Manipulates iptables to redirect traffic:
  ```
  /sbin/iptables -t nat -A PREROUTING -p tcp -s <src_ip> --dport <orig_port> -j REDIRECT --to-ports <bind_port>
  /sbin/iptables -I INPUT -p tcp -s <src_ip> -j ACCEPT
  ```
- Accepts the incoming connection on the bind socket.
- After shell session ends, cleans up iptables rules:
  ```
  /sbin/iptables -t nat -D PREROUTING -p tcp -s <src_ip> -j ACCEPT
  /sbin/iptables -D INPUT -p tcp -s <src_ip> -j ACCEPT
  ```

#### Mode 3: UDP Monitoring Probe (`mon`)
- Creates a UDP socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP).
- Sends a 1-byte response ("1" from rodata at 0x4041d5) back to the operator.
- This is a "ping" to confirm the implant is alive.

### 3.7 Self-Deployment (`to_open` at 0x401e63)

When called with `--init`, builds and executes this shell command via `system()`:

```
/bin/rm -f /dev/shm/<name>; /bin/cp <self> /dev/shm/<name> && /bin/chmod 755 /dev/shm/<name> && /dev/shm/<name> --init && /bin/rm -f /dev/shm/<name>
```

This copies the binary to tmpfs (`/dev/shm/`), runs it, and deletes it — the binary never persists on disk after initial deployment.

### 3.8 Encryption

- **Algorithm**: RC4 (textbook implementation at `rc4_init`/`rc4`).
- **Key**: Derived from the magic packet payload (bytes at offset +10 from packet data pointer).
- **Two separate RC4 contexts**: `crypt_ctx` (encrypt outgoing) and `decrypt_ctx` (decrypt incoming), both initialized with the same key.
- **Usage**: All shell I/O is RC4-encrypted via `cread()`/`cwrite()`.

---

## 4. Anti-Forensics Techniques

| Technique | Implementation |
|---|---|
| **No listening port** | Raw socket with BPF filter — invisible to `netstat`/`ss` |
| **Process masquerading** | `prctl(PR_SET_NAME)` + argv[0] overwrite with legitimate daemon names |
| **Stack string obfuscation** | Passwords, paths, and commands built char-by-char on the stack to evade `strings` |
| **tmpfs execution** | Copies self to `/dev/shm/`, runs from RAM, deletes from disk |
| **Timestamp manipulation** | `utimes()` preserves original file timestamps |
| **PID file masquerading** | `/var/run/haldrund.pid` mimics a legitimate HAL daemon |
| **Encrypted C2** | RC4-encrypted shell sessions |
| **Firewall manipulation** | Dynamic iptables rules added/removed per session |
| **Multi-protocol activation** | Can be activated via TCP, UDP, or ICMP — any one could be allowed through firewalls |
| **Double fork** | Full daemonization with `daemon()` + additional `fork()`/`setsid()` on activation |

---

## 5. Indicators of Compromise (IoCs)

### 5.1 File Hashes

| Hash | Value |
|---|---|
| SHA256 | `fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73` |
| MD5 | `0017f7b913ce66e4d80f7e78cf830a2b` |
| SHA1 | `f1bf775746a5c882b9ec003617b2a70cf5a5029` |
| Build ID | `1e3c06cce8dc23d9bf96c3a524404122bc281c71` |

### 5.2 File System Artifacts

| Path | Purpose |
|---|---|
| `/var/run/haldrund.pid` | PID lock file (persistence indicator) |
| `/dev/shm/*` | Temporary execution location (may be cleaned up) |

### 5.3 Network Indicators

| Indicator | Value |
|---|---|
| BPF magic (UDP dst port) | **29269** (0x7255) |
| BPF magic (TCP payload) | **0x5293** (21139) — first 2 bytes of TCP payload |
| BPF trigger (ICMP) | ICMP Echo Request (type 8) with payload |
| Bind shell port range | **42391–43390** (0xa597–0xa97e) |
| Raw socket type | `AF_PACKET, SOCK_RAW, ETH_P_ALL` (0x0800) |

### 5.4 Process Indicators

Processes masquerading as any of these names running with a raw socket open:

- `/sbin/udevd -d`
- `/sbin/mingetty /dev/tty7`
- `/usr/sbin/console-kit-daemon --no-daemon`
- `hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event`
- `dbus-daemon --system`
- `hald-runner`
- `pickup -l -t fifo -u`
- `avahi-daemon: chroot helper`
- `/sbin/auditd -n`
- `/usr/lib/systemd/systemd-journald`
- `/usr/libexec/postfix/master` (child process after activation)
- `qmgr -l -t fifo -u` (shell session)
- `kdmtmpflush`

### 5.5 iptables Artifacts

Look for dynamically added/removed rules matching these patterns:
```
iptables -t nat -A PREROUTING -p tcp -s <IP> --dport <PORT> -j REDIRECT --to-ports <PORT>
iptables -I INPUT -p tcp -s <IP> -j ACCEPT
```

### 5.6 Build/Compiler Artifacts

- Compiled with **GCC 4.8.5** (Red Hat 4.8.5-4) — consistent with CentOS 7 / RHEL 7 build environment.
- ABI target: Linux 2.6.32 (very old, maximizes compatibility).
- Source file: `a.c` — single-file implant.

### 5.7 Authentication Passwords

| Password | Function |
|---|---|
| `justforfun` | Triggers reverse shell connection |
| `socket` | Triggers iptables redirect + bind shell |

(These are RC4-encrypted in transit, but stored in plaintext in the binary built on the stack.)

---

## 6. Detection Strategies

### 6.1 Process-Level Detection
- Any process from the masquerading list above that has an open `AF_PACKET` raw socket (check `/proc/<pid>/net/packet` or `fd` links to `socket:[...]` with protocol 0x0003).
- Process with cmdline matching masquerade names but with anomalous `/proc/<pid>/exe` link (won't point to the expected binary path).
- Process with `/proc/<pid>/exe` pointing to `/dev/shm/*` or `(deleted)`.
- Process whose `/proc/<pid>/maps` shows a small executable (28KB) with no expected library mappings for the claimed daemon.

### 6.2 File System Detection
- Existence of `/var/run/haldrund.pid` (or any `haldrund*` artifact).
- ELF files in `/dev/shm/` (should never contain executables on a healthy system).
- Any file matching the hashes above.

### 6.3 Network Detection
- Raw packet socket opened by a non-network-monitoring process.
- TCP connections to ports 42391–43390 from unexpected sources.
- iptables rules containing `REDIRECT --to-ports` in the 42391–43390 range that weren't explicitly configured.
- ICMP echo requests with unusual payload sizes or content.
- UDP traffic to port 29269.

### 6.4 Memory/Runtime Detection
- Strings `justforfun`, `socket`, or `haldrund` in process memory.
- RC4 S-box patterns in process memory (256-byte array with permutation).
- BPF filter attached to a raw socket (inspectable via `SO_GET_FILTER`).

---

## 7. Notable Weaknesses in the Implant

1. **Not stripped**: Full symbol table present including function names like `getshell`, `packet_loop`, `logon`, `rc4_init`, `decrypt_ctx`, `crypt_ctx`. This is an operational security failure by the threat actor.
2. **Stack strings are incomplete**: The process masquerading names are in plaintext in `.rodata` — easily extractable with `strings`.
3. **Hardcoded passwords**: `justforfun` and `socket` are built on the stack but can be recovered via disassembly.
4. **Hardcoded port range**: The bind shell port range 42391–43390 is fixed and scannable.
5. **Fixed BPF magic values**: The magic numbers 29269, 0x5293, and ICMP type 8 are static and easily signature-matchable.
6. **No rootkit component**: The implant has no kernel module or LD_PRELOAD to hide itself from `/proc` — it relies entirely on process name masquerading.
7. **`system()` calls**: Uses `system()` for iptables and self-copy operations, which is noisy (spawns `/bin/sh -c`).

---

