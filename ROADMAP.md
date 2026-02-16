# CIS Audit Tool for Fedora 43 - Project Roadmap

## Project Overview
Read-only CIS benchmark audit tool for Fedora 43. Modular design, auto-detects desktop vs server, outputs JSON.

## Architecture
- **Detection Engine**: Scores environment type (desktop/server) based on multiple signals
- **Check Modules**: Individual CIS checks, loaded dynamically
- **Output Formatter**: JSON (extensible to Markdown later)
- **CLI**: Argument parsing, sudo handling, verbose modes

## Chunks

### Chunk 1: Project Scaffold + Detection Engine [COMPLETE]
**Files:**
- `src/core/detector.py` - Environment detection with scoring
- `src/core/__init__.py`
- `src/__init__.py`
- `tests/test_detector.py`

**Requirements:**
- Detect desktop signals: display managers (GDM, SDDM, LightDM), desktop sessions, graphical.target
- Detect server signals: sshd, nginx/httpd, databases, multi-user.target
- Scoring algorithm: weighted signals → desktop/server/unknown
- CLI override: `--force-desktop`, `--force-server`
- Unit tests for detection logic

**Done when:** Detection works reliably, tests pass

---

### Chunk 2: CLI + Privilege Handling [COMPLETE]
**Files:**
- `src/cli.py` - Argument parsing, main entry point, privilege handling
- `cis-audit.py` - Executable script

**Requirements:**
- Parse args: `--output`, `--verbose`, `--force-desktop`, `--force-server`, `--no-sudo`
- Check for sudo upfront
- If no sudo: warn, skip privileged checks, continue
- Exit codes: 0=success, 1=error, 2=warnings

---

### Chunk 3: Core Check Framework [COMPLETE]
**Files:**
- `src/core/check.py` - Base check class with CheckResult dataclass
- `src/core/registry.py` - Check registration and auto-discovery
- `src/checks/__init__.py` - Checks package initialization
- `tests/test_check_framework.py` - Integration tests

**Requirements:**
- Abstract base class for checks
- Auto-discovery of check modules
- Check metadata: id, name, description, severity, requires_root
- Result object: passed/failed/skipped, message, remediation hint

**Done when:** Framework supports check registration, discovery, and execution

---

### Chunk 4: Initial CIS Checks (Authentication) [COMPLETE]
**Files:**
- `src/checks/auth_*.py` - 5 auth-related checks

**Checks:**
- Password complexity (pam configuration) ✓
- Account lockout policy ✓
- Password expiration ✓
- Empty password accounts ✓
- Root login restrictions (SSH) ✓

**Status:** All 5 authentication checks implemented with proper CIS compliance logic.

---

### Chunk 5: Logging & Auditing Checks [COMPLETE]
**Files:**
- `src/checks/logging_rsyslog.py` - rsyslog service check
- `src/checks/logging_auditd.py` - auditd service check
- `src/checks/logging_permissions.py` - log file permissions check
- `src/checks/logging_remote.py` - remote logging configuration check
- `src/checks/logging_audit_rules.py` - audit rules configuration check

**Checks:**
- rsyslog installed and running ✓
- auditd installed and running ✓
- Log file permissions ✓
- Remote logging configured ✓
- Audit rules present ✓

---

### Chunk 6: Network & Firewall Checks [COMPLETE]
**Files:**
- `src/checks/network_firewalld.py` - firewalld service status check ✓
- `src/checks/network_default_zone.py` - default zone configuration check ✓
- `src/checks/network_ipv6.py` - IPv6 configuration check ✓
- `src/checks/network_tcp_wrappers.py` - TCP wrappers configuration check ✓
- `src/checks/network_services.py` - suspicious network services check ✓

**Checks:**
- firewalld installed, running, and enabled ✓
- Default zone configured with reasonable restrictions ✓
- IPv6 disabled (informational) ✓
- TCP wrappers configured with hosts.allow/deny ✓
- Suspicious network services detection ✓

---

### Chunk 7: Filesystem & Permissions Checks [COMPLETE]
**Files:**
- `src/checks/fs_tmp_mount.py` - /tmp mount options check ✓
- `src/checks/fs_var_tmp.py` - /var/tmp permissions check ✓
- `src/checks/fs_world_writable.py` - World-writable files check ✓
- `src/checks/fs_suid_sgid.py` - SUID/SGID audit check ✓
- `src/checks/fs_home_permissions.py` - Home directory permissions check ✓

**Checks:**
- /tmp mounted with noexec,nosuid,nodev ✓
- /var/tmp permissions with sticky bit ✓
- World-writable files outside temp directories ✓
- SUID/SGID files audit with whitelist ✓
- Home directory permissions (including /root) ✓

---

### Chunk 8: JSON Output Formatter [COMPLETE]
**Files:**
- `src/output/json_formatter.py` - JSON formatter with metadata, summary, and check details
- `src/output/__init__.py` - Output package initialization
- `tests/test_json_formatter.py` - Comprehensive tests for JSON formatting

**Requirements:**
- Structured JSON output ✓
- Metadata: timestamp, hostname, f43 version, environment type ✓
- Summary: total checks, passed, failed, skipped ✓
- Per-check details: id, name, result, message, remediation ✓
- Pretty-print option ✓
- Datetime serialization handling ✓
- CLI integration with `--pretty` flag ✓

---

### Chunk 9: Integration & End-to-End Test [COMPLETE]
**Files:**
- `tests/test_integration.py` - 48 comprehensive integration tests
- `README.md` - Complete project documentation

**Requirements:**
- Full tool runs without errors ✓
- Output validates against schema ✓
- Documentation: usage, examples, extending checks ✓

**Tests Include:**
- End-to-end audit flow with mocked checks
- CLI argument combinations (all flags tested)
- Privilege checking with/without sudo
- JSON output schema validation
- Exit codes (0=success, 1=error, 2=warnings)
- Environment detection integration
- Mocked external dependencies (systemctl, rpm)
- Real check discovery and execution

---

### Chunk 10: Polish & Extension Points [COMPLETE]
**Files:**
- `DESIGN.md` - Architecture decisions
- `CONTRIBUTING.md` - How to add checks

**Requirements:**
- Code review, refactor if needed ✓
- DESIGN.md: High-level architecture, component breakdown, design decisions, extension points, security considerations ✓
- CONTRIBUTING.md: Development setup, code style, how to add checks/formatters, testing requirements, example template ✓
- Fix test_severity_comparison test ✓

**Deliverables:**
- `DESIGN.md` (15KB+) - Complete architecture documentation with ASCII diagrams
- `CONTRIBUTING.md` (21KB+) - Comprehensive developer guide with step-by-step instructions
- All 144 tests passing

---

### Chunk 11: Import Cleanup [COMPLETE]
**Files:**
- All Python source files

**Requirements:**
- Move all imports to top of files ✓
- Remove duplicate imports ✓
- Follow PEP 8 import order ✓

---

### Chunk 12: CLI Progress Bar [COMPLETE]
**Files:**
- `src/output/progress.py` - Progress bar implementation
- `src/output/__init__.py` - Export progress classes
- `src/core/registry.py` - Progress callback support
- `src/cli.py` - Progress bar integration

**Requirements:**
- Custom progress bar implementation (no external dependencies) ✓
- Progress callbacks in CheckRegistry.run_all() ✓
- Show check number, name, status (✓/✗/⊘) ✓
- Show percentage complete, elapsed time, estimated time remaining ✓
- Color coding: green=passed, red=failed, yellow=skipped ✓
- Graceful fallback for non-TTY output ✓
- `--no-progress` flag to disable ✓
- Works with --verbose mode and file output ✓
- NullProgressBar for when progress is disabled ✓

**Deliverables:**
- Progress bar with visual indicators and timing information
- All 144 tests passing

### Chunk 13: Web Viewer [COMPLETE]
**Files:**
- `viewer/index.html` - Single page application with dashboard layout
- `viewer/style.css` - Minimalist dark theme styling
- `viewer/app.js` - Vanilla JS application logic

**Requirements:**
- Clean, modern design with dark mode default ✓
- File input to load JSON audit results ✓
- Dashboard with header, summary cards, severity chart ✓
- Filter/search functionality ✓
- Expandable check details ✓
- Export filtered results ✓
- Keyboard shortcuts ✓
- No external dependencies ✓
- Works offline (file:// protocol) ✓
- Responsive design ✓

**Deliverables:**
- Professional web viewer with all features implemented
- Updated README.md with viewer documentation
- All 144 tests still passing

### Chunk 14: SSH Hardening Checks (CIS 5.1.x) [COMPLETE]
**Files:**
- `src/checks/ssh_config_permissions.py` - SSH config file permissions ✓
- `src/checks/ssh_protocol.py` - SSH protocol version check ✓
- `src/checks/ssh_loglevel.py` - SSH log level configuration ✓
- `src/checks/ssh_x11.py` - SSH X11 forwarding check ✓
- `src/checks/ssh_maxauthtries.py` - SSH max authentication attempts ✓
- `src/checks/ssh_ignorerhosts.py` - SSH ignore rhosts check ✓
- `src/checks/ssh_hostbasedauth.py` - SSH host-based authentication ✓
- `src/checks/ssh_permitemptypasswords.py` - SSH empty passwords ✓
- `src/checks/ssh_permituserenv.py` - SSH user environment ✓
- `src/checks/ssh_ciphers.py` - SSH cipher configuration ✓
- `src/checks/ssh_idle_timeout.py` - SSH idle timeout ✓
- `src/checks/ssh_logingracetime.py` - SSH login grace time ✓

**Checks:**
- SSH config file permissions (600 for host keys, 644 for config) ✓
- Protocol version 2 only ✓
- LogLevel set to INFO or VERBOSE ✓
- X11 forwarding disabled ✓
- MaxAuthTries set to 4 or less ✓
- IgnoreRhosts enabled ✓
- HostbasedAuthentication disabled ✓
- PermitEmptyPasswords disabled ✓
- PermitUserEnvironment disabled ✓
- Strong ciphers and MACs configured ✓
- ClientAliveInterval and ClientAliveCountMax configured ✓
- LoginGraceTime set to 60 seconds or less ✓

### Chunk 15: Network Kernel Parameters (CIS 3.1.x, 3.2.x) [COMPLETE]
**Files:**
- `src/checks/net_ip_forward.py` - IP forwarding check ✓
- `src/checks/net_packet_redirect.py` - Packet redirect check ✓
- `src/checks/net_source_routing.py` - Source routing check ✓
- `src/checks/net_icmp_redirects.py` - ICMP redirects check ✓
- `src/checks/net_secure_icmp_redirects.py` - Secure ICMP redirects check ✓
- `src/checks/net_log_martians.py` - Log martians check ✓
- `src/checks/net_ignore_broadcasts.py` - Ignore broadcasts check ✓
- `src/checks/net_ignore_bogus_errors.py` - Ignore bogus errors check ✓
- `src/checks/net_rp_filter.py` - Reverse path filtering check ✓
- `src/checks/net_tcp_syncookies.py` - TCP SYN cookies check ✓

**Checks:**
- IP forwarding disabled ✓
- Packet redirect sending disabled ✓
- Source routing disabled ✓
- ICMP redirects disabled ✓
- Secure ICMP redirects disabled ✓
- Suspicious packets logged ✓
- Broadcast ICMP requests ignored ✓
- Bogus error responses ignored ✓
- Reverse path filtering enabled ✓
- TCP SYN cookies enabled ✓

### Chunk 16: Boot Security Checks (CIS 1.4.x, 1.5.x) [COMPLETE]
**Files:**
- `src/checks/boot_grub_password.py` - GRUB password protection ✓
- `src/checks/boot_grub_permissions.py` - GRUB file permissions ✓
- `src/checks/boot_single_user_auth.py` - Single user authentication ✓

**Checks:**
- GRUB bootloader password configured ✓
- GRUB configuration file permissions (600) ✓
- Single user mode requires authentication ✓

### Chunk 17: SELinux Checks (CIS 1.3.x) [COMPLETE]
**Files:**
- `src/checks/selinux_installed.py` - SELinux installed check ✓
- `src/checks/selinux_bootloader.py` - SELinux bootloader check ✓
- `src/checks/selinux_policy.py` - SELinux policy check ✓
- `src/checks/selinux_enforcing.py` - SELinux enforcing mode check ✓
- `src/checks/selinux_unconfined.py` - SELinux unconfined processes check ✓
- `src/checks/selinux_setroubleshoot.py` - SELinux SETroubleshoot check ✓
- `src/checks/selinux_mcstrans.py` - SELinux MCS translation check ✓

**Checks:**
- SELinux packages installed ✓
- SELinux enabled in bootloader ✓
- Targeted policy configured ✓
- SELinux in enforcing mode ✓
- No unconfined daemons running ✓
- SETroubleshoot not installed (or properly configured) ✓
- MCS translation service not installed ✓

### Chunk 18: Additional Audit Rules (CIS 4.4.x) [COMPLETE]
**Files:**
- `src/checks/audit_network_changes.py` (4.4.9) - Network environment changes ✓
- `src/checks/audit_mac_changes.py` (4.4.10) - MAC (SELinux) changes ✓
- `src/checks/audit_dac_changes.py` (4.4.11) - DAC permission changes ✓
- `src/checks/audit_mounts.py` (4.4.12) - Filesystem mounts ✓
- `src/checks/audit_file_deletions.py` (4.4.13) - File deletion events ✓
- `src/checks/audit_sudoers.py` (4.4.14) - Sudoers changes ✓
- `src/checks/audit_sudolog.py` (4.4.15) - Sudo command execution ✓
- `src/checks/audit_kernel_modules.py` (4.4.16) - Kernel module load/unload ✓
- `src/checks/audit_immutable.py` (4.4.17) - Audit config immutable ✓
- `src/checks/audit_grub.py` (4.4.1.3-4.4.1.4) - Early audit and backlog ✓
- `src/checks/audit_storage.py` (4.4.2.1) - Log storage size ✓
- `src/checks/audit_retention.py` (4.4.2.2-4.4.2.3) - Log retention/full action ✓

**Checks:**
- Network environment changes monitored ✓
- SELinux/MAC configuration changes monitored ✓
- DAC permission changes monitored ✓
- Filesystem mount operations monitored ✓
- File deletion events monitored ✓
- Sudoers file changes monitored ✓
- Sudo command execution monitored ✓
- Kernel module load/unload monitored ✓
- Audit configuration immutable ✓
- Early boot auditing and backlog configured ✓
- Log storage size configured ✓
- Log retention and full action configured ✓

## Status Tracking

| Chunk | Status | Started | Finished | Notes |
|-------|--------|---------|----------|-------|
| 1 | COMPLETE | Feb 16 | Feb 16 | Detection engine with 34 unit tests |
| 2 | COMPLETE | Feb 16 | Feb 16 | CLI + privilege handling |
| 3 | COMPLETE | Feb 16 | Feb 16 | Check framework with 30+ integration tests |
| 4 | COMPLETE | Feb 16 | Feb 16 | 5 Authentication checks (password complexity, lockout, expiration, empty passwords, root SSH) |
| 5 | COMPLETE | Feb 16 | Feb 16 | 5 Logging checks (rsyslog, auditd, log permissions, remote logging, audit rules) |
| 6 | COMPLETE | Feb 16 | Feb 16 | 5 Network checks (firewalld, default zone, IPv6, TCP wrappers, network services) |
| 7 | COMPLETE | Feb 16 | Feb 16 | 5 Filesystem checks (/tmp mount, /var/tmp perms, world-writable, SUID/SGID, home perms) |
| 8 | COMPLETE | Feb 16 | Feb 16 | JSON output formatter with metadata, summary, severity breakdown |
| 9 | COMPLETE | Feb 16 | Feb 16 | Integration tests (48 tests) + README documentation |
| 10 | COMPLETE | Feb 16 | Feb 16 | DESIGN.md + CONTRIBUTING.md documentation, all tests passing |
| 11 | COMPLETE | Feb 16 | Feb 16 | Fixed import statements across all Python files - moved all imports to top, removed duplicates, followed PEP 8 order |
| 12 | COMPLETE | Feb 16 | Feb 16 | CLI progress bar with visual indicators, timing, color coding, and --no-progress flag |
| 13 | COMPLETE | Feb 16 | Feb 16 | Web viewer with dark theme, filters, search, export, keyboard shortcuts - no dependencies |
| 14 | COMPLETE | Feb 16 | Feb 17 | 12 SSH hardening checks (protocol, ciphers, auth, timeouts, permissions) |
| 15 | COMPLETE | Feb 16 | Feb 17 | 10 Network kernel parameter checks (IP forwarding, redirects, routing, syncookies) |
| 16 | COMPLETE | Feb 16 | Feb 17 | 3 Boot security checks (GRUB password, permissions, single user auth) |
| 17 | COMPLETE | Feb 16 | Feb 17 | 7 SELinux checks (installed, bootloader, policy, enforcing, unconfined, setroubleshoot, mcstrans) |
| 18 | COMPLETE | Feb 17 | Feb 17 | 12 Additional audit rule checks (network, MAC, DAC, mounts, deletions, sudoers, sudolog, kernel modules, immutable, GRUB, storage, retention) |
| 19 | COMPLETE | Feb 17 | Feb 17 | 9 Filesystem mount checks (partition separation, /dev/shm options, automount, USB storage, AIDE) |
| 20 | COMPLETE | Feb 17 | Feb 17 | 4 Process hardening checks (core dumps, ASLR, prelink, ptrace) |
| 21 | COMPLETE | Feb 17 | Feb 17 | 17 Service audit checks (xinetd, avahi, cups, dhcp, ldap, nfs, dns, ftp, http, imap, samba, proxy, snmp, postfix, rsync, nis) |
| 22 | COMPLETE | Feb 17 | Feb 17 | 10 System file permission checks (/etc/passwd, shadow, group, gshadow, shells, opasswd and backups) |
| 23 | COMPLETE | Feb 17 | Feb 17 | 12 User/group validation checks (shadowed passwords, unique IDs/names, root PATH, home directories, dot files) |
| 24 | COMPLETE | Feb 17 | Feb 17 | 6 Warning banner checks (/etc/motd, /etc/issue, /etc/issue.net with permissions) |
| 25 | COMPLETE | Feb 17 | Feb 17 | 3 Time synchronization checks (sync enabled, chrony, timesyncd) |
| 26 | COMPLETE | Feb 17 | Feb 17 | 9 Cron/at restriction checks (daemon, permissions, authorized users) |
| 27 | COMPLETE | Feb 17 | Feb 17 | 4 Uncommon protocol checks (DCCP, SCTP, RDS, TIPC) |
| 28 | COMPLETE | Feb 17 | Feb 17 | 6 PAM + User account checks (password reuse, hashing, inactive lock, system accounts, umask, shell timeout) |
| 29 | COMPLETE | Feb 17 | Feb 17 | 8 SSH server extra checks (banner, PAM, allow/deny users, max sessions, ciphers/MACs, KEX, host key perms) |
| 30 | COMPLETE | Feb 17 | Feb 17 | 7 SSH client checks (ciphers, MACs, KEX, host auth, protocol, strict host, user env) |
| 31 | COMPLETE | Feb 17 | Feb 17 | 5 iptables checks (installed, default deny, loopback, established, open ports) |
| 32 | COMPLETE | Feb 17 | Feb 17 | 3 Additional checks (last password change, kernel exec-shield, NTP server) |
| 33 | COMPLETE | Feb 17 | Feb 17 | 5 GDM settings + logrotate checks (banner, disable-user-list, XDCMP, logrotate installed/configured) |
| 34 | COMPLETE | Feb 17 | Feb 17 | Final 6 checks + --full/--include-expensive support |
| 35 | COMPLETE | Feb 17 | Feb 17 | Platform abstraction core with profile loader, adapters, and platform tests |
| 36 | COMPLETE | Feb 17 | Feb 17 | PlatformContext wired through framework, CLI, JSON output, and tests |
| 37 | COMPLETE | Feb 17 | Feb 17 | Pilot check migration to platform adapters (detector + 5 checks) |
| 38 | COMPLETE | Feb 17 | Feb 17 | Bulk migration of service checks (`svc_*`) to platform helpers |
| 39 | COMPLETE | Feb 17 | Feb 17 | Path and metadata generalization with compatibility |
| 40 | IN PROGRESS | Feb 17 | - | Second distro pilot profile and validation |
| 41 | COMPLETE | Feb 17 | Feb 17 | Production hardening (CLI robustness, discovery diagnostics, output reliability) |

### Chunk 19: Filesystem Mount Options (CIS 1.1.x) [COMPLETE]
**Files:**
- `src/checks/fs_partition_var.py` - /var partition check ✓
- `src/checks/fs_partition_var_log.py` - /var/log partition check ✓
- `src/checks/fs_partition_var_log_audit.py` - /var/log/audit partition check ✓
- `src/checks/fs_partition_home.py` - /home partition check ✓
- `src/checks/fs_dev_shm.py` - /dev/shm mount options check ✓
- `src/checks/fs_automount.py` - Automounting disabled check ✓
- `src/checks/fs_usb_storage.py` - USB storage disabled check ✓
- `src/checks/fs_aide.py` - AIDE installed check ✓
- `src/checks/fs_aide_cron.py` - AIDE cron job check ✓

**Checks:**
- Separate partition for /var ✓
- Separate partition for /var/log ✓
- Separate partition for /var/log/audit ✓
- Separate partition for /home ✓
- /dev/shm mounted with nodev, nosuid, noexec ✓
- Automounting disabled ✓
- USB storage disabled ✓
- AIDE filesystem integrity checker installed ✓
- AIDE filesystem integrity checks scheduled ✓

### Chunk 20: Process Hardening (CIS 1.4.x) [COMPLETE]
**Files:**
- `src/checks/proc_core_dumps.py` - Core dumps restricted ✓
- `src/checks/proc_aslr.py` - ASLR enabled ✓
- `src/checks/proc_prelink.py` - Prelink disabled ✓
- `src/checks/proc_ptrace.py` - Ptrace scope restricted ✓

**Checks:**
- Core dumps restricted via limits.conf and sysctl ✓
- Address space layout randomization (ASLR) enabled ✓
- Prelink package not installed ✓
- Ptrace scope restricted to root-only ✓

### Chunk 21: Service Audits (CIS 2.2.x, 2.3.x) [COMPLETE]
**Files:**
- `src/checks/svc_xinetd.py` - xinetd not installed ✓
- `src/checks/svc_avahi.py` - Avahi not installed ✓
- `src/checks/svc_cups.py` - CUPS not installed ✓
- `src/checks/svc_dhcp_server.py` - DHCP server not installed ✓
- `src/checks/svc_ldap_server.py` - LDAP server not installed ✓
- `src/checks/svc_nfs.py` - NFS not installed ✓
- `src/checks/svc_dns_server.py` - DNS server not installed ✓
- `src/checks/svc_ftp_server.py` - FTP server not installed ✓
- `src/checks/svc_http_server.py` - HTTP server not installed ✓
- `src/checks/svc_imap_server.py` - IMAP/POP3 not installed ✓
- `src/checks/svc_samba.py` - Samba not installed ✓
- `src/checks/svc_proxy_server.py` - HTTP proxy not installed ✓
- `src/checks/svc_snmp_server.py` - SNMP server not installed ✓
- `src/checks/svc_postfix.py` - Postfix local-only mode ✓
- `src/checks/svc_rsync.py` - rsync not installed ✓
- `src/checks/svc_nis_server.py` - NIS server not installed ✓
- `src/checks/svc_nis_client.py` - NIS client not installed ✓

**Checks:**
- 17 unnecessary service checks for server hardening ✓

### Chunk 22: System File Permissions (CIS 6.1.x) [COMPLETE]
**Files:**
- `src/checks/perm_passwd.py` - /etc/passwd permissions ✓
- `src/checks/perm_passwd_backup.py` - /etc/passwd- permissions ✓
- `src/checks/perm_group.py` - /etc/group permissions ✓
- `src/checks/perm_group_backup.py` - /etc/group- permissions ✓
- `src/checks/perm_shadow.py` - /etc/shadow permissions ✓
- `src/checks/perm_shadow_backup.py` - /etc/shadow- permissions ✓
- `src/checks/perm_gshadow.py` - /etc/gshadow permissions ✓
- `src/checks/perm_gshadow_backup.py` - /etc/gshadow- permissions ✓
- `src/checks/perm_shells.py` - /etc/shells permissions ✓
- `src/checks/perm_opasswd.py` - /etc/opasswd permissions ✓

**Checks:**
- 10 system file permission checks (root:root, 644/640/600) ✓

### Chunk 23: User/Group Validation (CIS 6.2.x) [COMPLETE]
**Files:**
- `src/checks/user_shadowed_passwords.py` - All passwords shadowed ✓
- `src/checks/user_no_empty_shadow.py` - No empty shadow passwords ✓
- `src/checks/user_group_consistency.py` - Group consistency ✓
- `src/checks/user_unique_uid.py` - Unique UIDs ✓
- `src/checks/user_unique_gid.py` - Unique GIDs ✓
- `src/checks/user_unique_name.py` - Unique usernames ✓
- `src/checks/user_unique_group_name.py` - Unique group names ✓
- `src/checks/user_root_path.py` - Root PATH integrity ✓
- `src/checks/user_root_only_uid0.py` - Root only UID 0 ✓
- `src/checks/user_home_dirs_exist.py` - Home directories exist ✓
- `src/checks/user_home_perms.py` - Home directory permissions ✓
- `src/checks/user_dotfile_perms.py` - Dot file permissions ✓

**Checks:**
- 12 user and group validation checks ✓

### Chunk 24: Warning Banners (CIS 1.6.x) [COMPLETE]
**Files:**
- `src/checks/banner_motd.py` - /etc/motd warning banner ✓
- `src/checks/banner_issue.py` - /etc/issue warning banner ✓
- `src/checks/banner_issue_net.py` - /etc/issue.net warning banner ✓
- `src/checks/banner_motd_perms.py` - /etc/motd permissions ✓
- `src/checks/banner_issue_perms.py` - /etc/issue permissions ✓
- `src/checks/banner_issue_net_perms.py` - /etc/issue.net permissions ✓

**Checks:**
- Warning banners present on all login/access points ✓
- Banner files have proper permissions (644, root:root) ✓

### Chunk 25: Time Synchronization (CIS 2.1.x) [COMPLETE]
**Files:**
- `src/checks/time_sync_enabled.py` - Time synchronization enabled ✓
- `src/checks/time_chrony.py` - Chrony configured ✓
- `src/checks/time_timesyncd.py` - systemd-timesyncd configured ✓

**Checks:**
- Time synchronization service is enabled ✓
- Chrony or systemd-timesyncd is properly configured ✓

### Chunk 26: Cron/At Restrictions (CIS 4.1.x) [COMPLETE]
**Files:**
- `src/checks/cron_daemon.py` - Cron daemon enabled ✓
- `src/checks/cron_crontab_perms.py` - /etc/crontab permissions ✓
- `src/checks/cron_hourly_perms.py` - /etc/cron.hourly permissions ✓
- `src/checks/cron_daily_perms.py` - /etc/cron.daily permissions ✓
- `src/checks/cron_weekly_perms.py` - /etc/cron.weekly permissions ✓
- `src/checks/cron_monthly_perms.py` - /etc/cron.monthly permissions ✓
- `src/checks/cron_d_perms.py` - /etc/cron.d permissions ✓
- `src/checks/cron_restricted.py` - Cron restricted to authorized users ✓
- `src/checks/at_restricted.py` - At restricted to authorized users ✓

**Checks:**
- Cron daemon is enabled and running ✓
- All cron directories have proper permissions (700, root:root) ✓
- Cron and at are restricted to authorized users only ✓

### Chunk 27: Uncommon Protocols (CIS 3.5.x) [COMPLETE]
**Files:**
- `src/checks/net_proto_dccp.py` - DCCP protocol disabled ✓
- `src/checks/net_proto_sctp.py` - SCTP protocol disabled ✓
- `src/checks/net_proto_rds.py` - RDS protocol disabled ✓
- `src/checks/net_proto_tipc.py` - TIPC protocol disabled ✓

**Checks:**
- DCCP, SCTP, RDS, TIPC protocols are disabled ✓

### Chunk 28: PAM + User Account Settings (CIS 5.3.x, 5.4.x) [COMPLETE]
**Files:**
- `src/checks/auth_password_reuse.py` (5.3.3) - Password reuse limited (pam_pwhistory) ✓
- `src/checks/auth_password_hash.py` (5.3.4) - Password hashing SHA-512/yescrypt (pam_unix) ✓
- `src/checks/user_inactive_lock.py` (5.4.1.4) - Inactive password lock ≤ 30 days ✓
- `src/checks/user_system_accounts.py` (5.4.2) - System accounts secured ✓
- `src/checks/user_umask.py` (5.4.4) - Default umask 027 or more restrictive ✓
- `src/checks/user_shell_timeout.py` (5.4.5) - Shell timeout ≤ 900 seconds ✓

**Checks:**
- Password reuse limited with pam_pwhistory (remember ≥ 24) ✓
- Strong password hashing algorithm (SHA-512 or yescrypt) ✓
- Inactive accounts locked after 30 days ✓
- System accounts have no login shell and are locked ✓
- Default umask is 027 or more restrictive ✓
- Shell timeout configured for idle sessions (≤ 900s) ✓

### Chunk 29: SSH Server Extras (CIS 5.1.x continued) [COMPLETE]
**Files:**
- `src/checks/ssh_banner.py` - SSH warning banner configured ✓
- `src/checks/ssh_pam_enabled.py` - SSH PAM enabled ✓
- `src/checks/ssh_allow_users.py` - SSH AllowUsers/AllowGroups configured ✓
- `src/checks/ssh_deny_users.py` - SSH DenyUsers/DenyGroups configured ✓
- `src/checks/ssh_maxsessions.py` - SSH MaxSessions ≤ 10 ✓
- `src/checks/ssh_ciphers_mac.py` - SSH ciphers and MACs strong ✓
- `src/checks/ssh_kex.py` - SSH key exchange algorithms strong ✓
- `src/checks/ssh_host_keys_perms.py` - SSH host keys permissions ✓

**Checks:**
- SSH warning banner configured ✓
- PAM enabled for SSH authentication ✓
- AllowUsers/AllowGroups restricts SSH access ✓
- DenyUsers/DenyGroups blocks unwanted users ✓
- MaxSessions limited to 10 or less ✓
- Strong ciphers and MACs configured ✓
- Strong key exchange algorithms ✓
- Host key files have proper permissions ✓

### Chunk 30: SSH Client Checks (CIS 5.2.x) [COMPLETE]
**Files:**
- `src/checks/ssh_client_ciphers.py` - SSH client ciphers strong ✓
- `src/checks/ssh_client_macs.py` - SSH client MACs strong ✓
- `src/checks/ssh_client_kex.py` - SSH client key exchange strong ✓
- `src/checks/ssh_client_host_auth.py` - SSH client host-based auth disabled ✓
- `src/checks/ssh_client_protocol.py` - SSH client protocol version 2 ✓
- `src/checks/ssh_client_strict_host.py` - SSH client strict host key checking ✓
- `src/checks/ssh_client_user_env.py` - SSH client user environment disabled ✓

**Checks:**
- SSH client uses strong ciphers ✓
- SSH client uses strong MACs ✓
- SSH client uses strong key exchange algorithms ✓
- SSH client host-based authentication disabled ✓
- SSH client protocol version 2 only ✓
- SSH client strict host key checking enabled ✓
- SSH client user environment variables disabled ✓

### Chunk 31: iptables Checks (CIS 3.6.x) [COMPLETE]
**Files:**
- `src/checks/iptables_installed.py` - iptables installed ✓
- `src/checks/iptables_default_deny.py` - iptables default deny policy ✓
- `src/checks/iptables_loopback.py` - iptables loopback traffic configured ✓
- `src/checks/iptables_established.py` - iptables established connections ✓
- `src/checks/iptables_open_ports.py` - iptables rules for open ports ✓

**Checks:**
- iptables package installed ✓
- Default deny policy configured ✓
- Loopback traffic properly handled ✓
- Established connections allowed ✓
- Firewall rules exist for all open ports ✓

### Chunk 32: Additional User/Group Checks [COMPLETE]
**Files:**
- `src/checks/user_last_password_change.py` (5.4.1.4) - Last password change in past ✓
- `src/checks/kernel_exec_shield.py` - Kernel exec-shield enabled ✓
- `src/checks/svc_ntp.py` - NTP server not installed ✓

**Checks:**
- All users' last password change date is in the past ✓
- Kernel exec-shield protection enabled (or NX bit supported) ✓
- NTP server not installed (use chrony/timesyncd instead) ✓

### Chunk 33: GDM Settings + Logrotate (CIS 1.7.x, 4.3.x) [COMPLETE]
**Files:**
- `src/checks/gdm_banner.py` (1.7.2) - GDM login banner configured ✓
- `src/checks/gdm_disable_user_list.py` (1.7.3) - GDM disable-user-list enabled ✓
- `src/checks/gdm_xdcmp.py` (1.7.4) - GDM XDCMP not enabled ✓
- `src/checks/logrotate_installed.py` (4.3.1) - logrotate installed ✓
- `src/checks/logrotate_configured.py` (4.3.2) - logrotate configured ✓

**Checks:**
- GDM login banner is configured with warning message ✓
- GDM user list is disabled on login screen ✓
- XDCMP is not enabled in GDM configuration ✓
- logrotate is installed for log management ✓
- logrotate is properly configured with rotation settings ✓

### Chunk 34: Final 6 Checks for 100% Coverage + --full Flag [COMPLETE]
**Files:**
- `src/checks/selinux_apparmor_installed.py` (1.5.2) - AppArmor installed (optional for Fedora) ✓
- `src/checks/selinux_apparmor_enabled.py` (1.5.3) - AppArmor enabled (optional for Fedora) ✓
- `src/checks/gdm_removed.py` (1.7.1) - GDM removed (optional for servers) ✓
- `src/checks/svc_xorg_server.py` (2.2.2) - xorg-x11-server-common removed (optional for servers) ✓
- `src/checks/fs_unowned_files.py` (6.1.12) - Unowned files check (expensive scan) ✓
- `src/checks/fs_ungrouped_files.py` (6.1.13) - Ungrouped files check (expensive scan) ✓

**Framework Updates:**
- Added `expensive: bool = False` attribute to BaseCheck ✓
- Added `optional: bool = False` attribute to BaseCheck ✓
- Added `--full` flag to CLI to include expensive/optional checks ✓
- Added `--include-expensive` flag as alias for `--full` ✓
- Modified CheckRegistry.run_all() to filter expensive checks unless flag is set ✓

**Checks:**
- AppArmor installed check (optional - Fedora uses SELinux) ✓
- AppArmor enabled check (optional - Fedora uses SELinux) ✓
- GDM removed for server hardening (optional - not for desktops) ✓
- Xorg X11 server not installed (optional - not for desktops) ✓
- No unowned files or directories (expensive filesystem scan) ✓
- No ungrouped files or directories (expensive filesystem scan) ✓

**Status:** CatoScan v3.5 - Production-ready baseline with multi-distro rollout in progress.

### Chunk 35: Multi-Distro Platform Abstraction Core [COMPLETE]
**Files:**
- `src/core/platform.py` - PlatformContext, profile loading, command adapters
- `src/platforms/base.json` - Base command/path/remediation defaults
- `src/platforms/fedora-43.json` - Fedora 43 profile override
- `src/core/check.py` - Platform context support in BaseCheck
- `src/core/registry.py` - Pass platform context to checks

**Requirements:**
- Detect distro info from `/etc/os-release`
- Load profile data from config templates
- Centralize package/service/path/remediation assumptions behind adapters
- Keep existing Fedora behavior as default compatibility profile

**Progress:**
- Platform module created with cached context loader and adapter helpers ✓
- Profile templates added for base + Fedora 43 ✓
- Framework wiring completed (BaseCheck + Registry + CLI + JSON formatter) ✓
- Platform metadata fields added to JSON output while preserving `fedora_version` compatibility ✓
- Platform abstraction test suite added (`tests/test_platform.py`) ✓

### Chunk 36: Framework-Wide Platform Context Usage [COMPLETE]
**Files:**
- `src/cli.py`
- `src/output/json_formatter.py`
- `tests/test_integration.py`
- `tests/test_json_formatter.py`

**Requirements:**
- Ensure CLI consistently initializes and propagates PlatformContext
- Include distro/profile metadata fields in output while keeping legacy compatibility
- Update integration tests for platform-aware output paths

**Progress:**
- CLI loads and propagates `PlatformContext` to registry/check execution ✓
- CLI supports `--profile` override for deterministic platform testing ✓
- JSON formatter emits `platform_profile`, distro, package/service manager metadata ✓
- Added integration and formatter tests for platform metadata and profile override ✓
- Existing integration and formatter tests remain green without regressions ✓

### Chunk 37: Pilot Migration - High-Leverage Checks [COMPLETE]
**Files:**
- `src/core/detector.py`
- `src/checks/time_sync_enabled.py`
- `src/checks/svc_avahi.py`
- `src/checks/svc_xinetd.py`
- `src/checks/network_firewalld.py`
- `src/checks/iptables_installed.py`

**Requirements:**
- Replace hardcoded `rpm`/`dnf`/`systemctl` usage with platform adapters
- Replace hardcoded remediation command strings with template rendering
- Preserve current pass/fail semantics on Fedora

**Progress:**
- Migrated checks:
  - `src/core/detector.py` now uses platform adapters for service/package/target checks ✓
  - `network_firewalld.py` ✓
  - `iptables_installed.py` ✓
  - `svc_avahi.py` ✓
  - `svc_xinetd.py` ✓
  - `time_sync_enabled.py` ✓

### Chunk 38: Bulk Service Check Migration [COMPLETE]
**Files:**
- `src/checks/svc_*.py` (remaining)

**Requirements:**
- Migrate repeated package/service helper logic to PlatformContext APIs
- Reduce duplicated distro-specific logic across service checks

**Progress:**
- Migrated package/service command logic for all `svc_*.py` checks to BaseCheck platform helpers ✓
- Direct package/service command calls removed from service checks (`rpm`: 0, `systemctl`: 0) ✓
- Remaining direct subprocess usage in service checks is now limited to check-specific logic:
  - `svc_postfix.py` (`postconf` parsing)
  - `svc_xorg_server.py` (`pgrep` process detection)
- Hardcoded `sudo dnf remove` strings eliminated from service checks (0 occurrences) ✓

### Chunk 39: Path + Metadata Generalization [COMPLETE]
**Files:**
- `src/checks/network_ipv6.py`
- `src/checks/boot_grub_permissions.py`
- `src/output/json_formatter.py`
- `README.md`
- `DESIGN.md`

**Requirements:**
- Move distro-specific path constants into platform profiles
- Add generic platform metadata fields in JSON output
- Keep `metadata.fedora_version` temporarily for backward compatibility

**Progress:**
- Added profile-driven network config path mappings (`network_config_paths`) in base/Fedora/Ubuntu profiles ✓
- Migrated `network_ipv6.py` to use platform path keys for distro-specific network config discovery ✓
- Migrated `boot_grub_permissions.py` to use platform GRUB file/directory path keys ✓
- Kept legacy `metadata.fedora_version` compatibility while emitting platform metadata fields ✓
- Migrated additional GRUB/path-heavy checks to platform-aware paths/commands:
  - `boot_grub_password.py` ✓
  - `selinux_bootloader.py` ✓
  - `audit_grub.py` ✓
  - `audit_network_changes.py` ✓
- Updated docs (`README.md`, `DESIGN.md`) with profile-aware usage and metadata fields ✓

### Chunk 40: Second Distro Pilot [IN PROGRESS]
**Files:**
- `src/platforms/ubuntu-24.04.json` (or alternate selected distro)
- Targeted checks and integration tests

**Requirements:**
- Add first non-Fedora profile
- Validate migrated checks on second distro target
- Document supported vs unsupported checks per distro

**Progress:**
- Added Ubuntu 24.04 profile template (`src/platforms/ubuntu-24.04.json`) ✓
- Added profile auto-detection test coverage for Ubuntu os-release matching ✓
- Added CLI profile override (`--profile`) to exercise alternate profiles in integration tests ✓
- Added platform-remediation tests validating Ubuntu command rendering for migrated checks ✓
- Documented profile support status and Ubuntu pilot caveats in `README.md` ✓
- Expanded Ubuntu package/service alias mappings for migrated service families ✓
- Added alias resolution test coverage (package + service alias fallback) ✓
- Expanded remediation verification tests for boot/audit/network checks under Ubuntu profile ✓

### Chunk 41: Production Hardening [COMPLETE]
**Files:**
- `src/cli.py`
- `src/core/registry.py`
- `catoscan.py`
- `tests/test_check_framework.py`
- `tests/test_integration.py`

**Requirements:**
- Improve CLI reliability and reduce ambiguous failure modes
- Surface check discovery/import failures without aborting full audit
- Ensure progress reporting reflects actual executed checks
- Add regression tests for hardened error handling paths

**Progress:**
- Removed duplicate privilege checks by passing privilege state through main audit flow ✓
- Improved output handling with explicit write-error messages and exit code 1 behavior ✓
- Added graceful broken pipe handling when output is piped to short-lived consumers ✓
- Progress bar now uses filtered check execution count instead of raw discovered count ✓
- Registry now records discovery/import errors and exposes diagnostics via `discovery_errors` ✓
- Added tests for discovery diagnostics and output-write failure handling ✓
- Updated entrypoint/help naming polish (`catoscan`) for production consistency ✓
- Added explicit CLI profile validation with clear available-profile errors ✓
- Hardened discovery module loading to avoid package-name collisions from import cache ✓
- Added metadata `schema_version` to stabilize JSON consumer contracts ✓
- Hardened user-account checks with username/home-path safety validation and diagnostic reporting ✓
- Added release prep artifacts (`CHANGELOG.md`) and bumped package version to `3.5.1` ✓
- Full regression suite passes: 169 tests ✓

## Notes
- All code: Python 3.11+
- Style: PEP 8, type hints
- Tests: pytest
- Target: Fedora 43 primary, multi-distro support in progress
