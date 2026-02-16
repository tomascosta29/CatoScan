"""
CIS Audit Tool for Fedora 43 - Checks Package

This package contains all CIS benchmark check implementations.
Each module should contain one or more check classes that inherit
from src.core.check.BaseCheck.
"""

# Export base classes for check implementations
from src.core.check import BaseCheck, CheckResult, Severity

# Import authentication checks
from src.checks.auth_password_complexity import PasswordComplexityCheck
from src.checks.auth_account_lockout import AccountLockoutCheck
from src.checks.auth_password_expiration import PasswordExpirationCheck
from src.checks.auth_empty_passwords import EmptyPasswordCheck
from src.checks.auth_root_ssh import RootSSHCheck
from src.checks.auth_password_reuse import PasswordReuseCheck
from src.checks.auth_password_hash import PasswordHashCheck

# Import SSH hardening checks (CIS 5.1.x)
from src.checks.ssh_config_permissions import SSHConfigPermissionsCheck
from src.checks.ssh_protocol import SSHProtocolCheck
from src.checks.ssh_loglevel import SSHLogLevelCheck
from src.checks.ssh_x11 import SSHX11Check
from src.checks.ssh_maxauthtries import SSHMaxAuthTriesCheck
from src.checks.ssh_ignorerhosts import SSHIgnoreRhostsCheck
from src.checks.ssh_hostbasedauth import SSHHostbasedAuthCheck
from src.checks.ssh_permitemptypasswords import SSHPermitEmptyPasswordsCheck
from src.checks.ssh_permituserenv import SSHPermitUserEnvCheck
from src.checks.ssh_ciphers import SSHCiphersCheck
from src.checks.ssh_idle_timeout import SSHIdleTimeoutCheck
from src.checks.ssh_logingracetime import SSHLoginGraceTimeCheck
# SSH server extras (CIS 5.1.x continued)
from src.checks.ssh_banner import SSHBannerCheck
from src.checks.ssh_pam_enabled import SSHPAMEnabledCheck
from src.checks.ssh_allow_users import SSHAllowUsersCheck
from src.checks.ssh_deny_users import SSHDenyUsersCheck
from src.checks.ssh_maxsessions import SSHMaxSessionsCheck
from src.checks.ssh_ciphers_mac import SSHCiphersMACCheck
from src.checks.ssh_kex import SSHKexCheck
from src.checks.ssh_host_keys_perms import SSHHostKeysPermsCheck
# SSH client checks (CIS 5.2.x)
from src.checks.ssh_client_ciphers import SSHClientCiphersCheck
from src.checks.ssh_client_macs import SSHClientMACsCheck
from src.checks.ssh_client_kex import SSHClientKexCheck
from src.checks.ssh_client_host_auth import SSHClientHostAuthCheck
from src.checks.ssh_client_protocol import SSHClientProtocolCheck
from src.checks.ssh_client_strict_host import SSHClientStrictHostCheck
from src.checks.ssh_client_user_env import SSHClientUserEnvCheck

# Import logging checks
from src.checks.logging_rsyslog import RsyslogCheck
from src.checks.logging_auditd import AuditdCheck
from src.checks.logging_permissions import LogPermissionsCheck
from src.checks.logging_remote import RemoteLoggingCheck
from src.checks.logging_audit_rules import AuditRulesCheck
# Import journald checks (CIS 4.2.2.x)
from src.checks.journald_rsyslog import JournaldRsyslogCheck
from src.checks.journald_compress import JournaldCompressCheck
from src.checks.journald_persistent import JournaldPersistentCheck

# Import logrotate checks (CIS 4.3.x)
from src.checks.logrotate_installed import LogrotateInstalledCheck
from src.checks.logrotate_configured import LogrotateConfiguredCheck

# Import cron/at restriction checks (CIS 4.1.x)
from src.checks.cron_daemon import CronDaemonCheck
from src.checks.cron_crontab_perms import CronCrontabPermsCheck
from src.checks.cron_hourly_perms import CronHourlyPermsCheck
from src.checks.cron_daily_perms import CronDailyPermsCheck
from src.checks.cron_weekly_perms import CronWeeklyPermsCheck
from src.checks.cron_monthly_perms import CronMonthlyPermsCheck
from src.checks.cron_d_perms import CronDPermsCheck
from src.checks.cron_restricted import CronRestrictedCheck
from src.checks.at_restricted import AtRestrictedCheck

# Import audit rule checks (CIS 4.4.x)
from src.checks.audit_network_changes import AuditNetworkChangesCheck
from src.checks.audit_mac_changes import AuditMACChangesCheck
from src.checks.audit_dac_changes import AuditDACChangesCheck
from src.checks.audit_mounts import AuditMountsCheck
from src.checks.audit_file_deletions import AuditFileDeletionsCheck
from src.checks.audit_sudoers import AuditSudoersCheck
from src.checks.audit_sudolog import AuditSudoLogCheck
from src.checks.audit_kernel_modules import AuditKernelModulesCheck
from src.checks.audit_immutable import AuditImmutableCheck
from src.checks.audit_grub import AuditGrubCheck
from src.checks.audit_storage import AuditStorageCheck
from src.checks.audit_retention import AuditRetentionCheck

# Import network checks
from src.checks.network_firewalld import FirewalldCheck
from src.checks.network_default_zone import FirewalldDefaultZoneCheck
from src.checks.network_ipv6 import IPv6Check
from src.checks.network_tcp_wrappers import TCPWrappersCheck
from src.checks.network_services import NetworkServicesCheck

# Import network kernel parameter checks (CIS 3.1.x, 3.2.x)
from src.checks.net_ip_forward import IPForwardCheck
from src.checks.net_packet_redirect import PacketRedirectCheck
from src.checks.net_source_routing import SourceRoutingCheck
from src.checks.net_icmp_redirects import ICMPRedirectsCheck
from src.checks.net_secure_icmp_redirects import SecureICMPRedirectsCheck
from src.checks.net_log_martians import LogMartiansCheck
from src.checks.net_ignore_broadcasts import IgnoreBroadcastsCheck
from src.checks.net_ignore_bogus_errors import IgnoreBogusErrorsCheck
from src.checks.net_rp_filter import RPFilterCheck
from src.checks.net_tcp_syncookies import TCPSyncookiesCheck
# Import uncommon protocol checks (CIS 3.5.x)
from src.checks.net_proto_dccp import DCCPProtocolCheck
from src.checks.net_proto_sctp import SCTPProtocolCheck
from src.checks.net_proto_rds import RDSProtocolCheck
from src.checks.net_proto_tipc import TIPCProtocolCheck
# Import iptables checks (CIS 3.6.x)
from src.checks.iptables_installed import IPTablesInstalledCheck
from src.checks.iptables_default_deny import IPTablesDefaultDenyCheck
from src.checks.iptables_loopback import IPTablesLoopbackCheck
from src.checks.iptables_established import IPTablesEstablishedCheck
from src.checks.iptables_open_ports import IPTablesOpenPortsCheck
# Import time synchronization checks (CIS 2.1.x)
from src.checks.time_sync_enabled import TimeSyncEnabledCheck
from src.checks.time_chrony import ChronyConfiguredCheck
from src.checks.time_timesyncd import TimesyncdConfiguredCheck

# Import NTP server check (complement to time sync)
from src.checks.svc_ntp import NTPServerNotInstalledCheck

# Import filesystem checks
from src.checks.fs_tmp_mount import TmpMountCheck
from src.checks.fs_var_tmp import VarTmpPermissionsCheck
from src.checks.fs_world_writable import WorldWritableFilesCheck
from src.checks.fs_suid_sgid import SuidSgidAuditCheck
from src.checks.fs_home_permissions import HomePermissionsCheck
# Import filesystem partition checks (CIS 1.1.x)
from src.checks.fs_partition_var import VarPartitionCheck
from src.checks.fs_partition_var_log import VarLogPartitionCheck
from src.checks.fs_partition_var_log_audit import VarLogAuditPartitionCheck
from src.checks.fs_partition_home import HomePartitionCheck
from src.checks.fs_dev_shm import DevShmMountCheck
from src.checks.fs_automount import AutomountDisabledCheck
from src.checks.fs_usb_storage import USBStorageDisabledCheck
# Import filesystem module checks (CIS 1.1.1.x)
from src.checks.fs_module_cramfs import CramfsModuleCheck
from src.checks.fs_module_freevxfs import FreevxfsModuleCheck
from src.checks.fs_module_jffs2 import Jffs2ModuleCheck
from src.checks.fs_module_hfs import HfsModuleCheck
from src.checks.fs_module_hfsplus import HfsplusModuleCheck
from src.checks.fs_module_squashfs import SquashfsModuleCheck
from src.checks.fs_module_udf import UdfModuleCheck
# Import AIDE checks (CIS 1.2.x)
from src.checks.fs_aide import AIDEInstalledCheck
from src.checks.fs_aide_cron import AIDECronCheck

# Import boot security checks
from src.checks.boot_grub_password import GrubPasswordCheck
from src.checks.boot_grub_permissions import GrubPermissionsCheck
from src.checks.boot_single_user_auth import SingleUserAuthCheck

# Import SELinux checks
from src.checks.selinux_installed import SELinuxInstalledCheck
from src.checks.selinux_bootloader import SELinuxBootloaderCheck
from src.checks.selinux_policy import SELinuxPolicyCheck
from src.checks.selinux_enforcing import SELinuxEnforcingCheck
from src.checks.selinux_unconfined import SELinuxUnconfinedCheck
from src.checks.selinux_setroubleshoot import SELinuxSETroubleshootCheck
from src.checks.selinux_mcstrans import SELinuxMcstransCheck
# Import AppArmor checks (optional for Fedora)
from src.checks.selinux_apparmor_installed import SELinuxAppArmorInstalledCheck
from src.checks.selinux_apparmor_enabled import SELinuxAppArmorEnabledCheck

# Import process hardening checks (CIS 1.4.x)
from src.checks.proc_core_dumps import CoreDumpsCheck
from src.checks.proc_aslr import ASLRCheck
from src.checks.proc_prelink import PrelinkCheck
from src.checks.proc_ptrace import PtraceCheck

# Import kernel exec-shield check
from src.checks.kernel_exec_shield import KernelExecShieldCheck

# Import warning banner checks (CIS 1.6.x)
from src.checks.banner_motd import BannerMotdCheck
from src.checks.banner_issue import BannerIssueCheck
from src.checks.banner_issue_net import BannerIssueNetCheck
from src.checks.banner_motd_perms import BannerMotdPermsCheck
from src.checks.banner_issue_perms import BannerIssuePermsCheck
from src.checks.banner_issue_net_perms import BannerIssueNetPermsCheck

# Import GDM settings checks (CIS 1.7.x)
from src.checks.gdm_banner import GDMBannerCheck
from src.checks.gdm_disable_user_list import GDMDisableUserListCheck
from src.checks.gdm_xdcmp import GDMXDCMPCheck
# Import GDM removal check (optional for servers)
from src.checks.gdm_removed import GDMRemovedCheck

# Import system file permission checks (CIS 6.1.x)
from src.checks.perm_passwd import PasswdPermissionsCheck
from src.checks.perm_passwd_backup import PasswdBackupPermissionsCheck
from src.checks.perm_group import GroupPermissionsCheck
from src.checks.perm_group_backup import GroupBackupPermissionsCheck
from src.checks.perm_shadow import ShadowPermissionsCheck
from src.checks.perm_shadow_backup import ShadowBackupPermissionsCheck
from src.checks.perm_gshadow import GshadowPermissionsCheck
from src.checks.perm_gshadow_backup import GshadowBackupPermissionsCheck
from src.checks.perm_shells import ShellsPermissionsCheck
from src.checks.perm_opasswd import OpasswdPermissionsCheck
# Import filesystem unowned/ungrouped checks (expensive scans)
from src.checks.fs_unowned_files import FSUnownedFilesCheck
from src.checks.fs_ungrouped_files import FSUngroupedFilesCheck

# Import service audit checks (CIS 2.2.x, 2.3.x)
from src.checks.svc_xinetd import XinetdNotInstalledCheck
from src.checks.svc_avahi import AvahiNotInstalledCheck
from src.checks.svc_cups import CUPSNotInstalledCheck
from src.checks.svc_dhcp_server import DHCPServerNotInstalledCheck
from src.checks.svc_ldap_server import LDAPServerNotInstalledCheck
from src.checks.svc_nfs import NFSNotInstalledCheck
from src.checks.svc_dns_server import DNSServerNotInstalledCheck
from src.checks.svc_ftp_server import FTPServerNotInstalledCheck
from src.checks.svc_http_server import HTTPServerNotInstalledCheck
from src.checks.svc_imap_server import IMAPPO3ServerNotInstalledCheck
from src.checks.svc_samba import SambaNotInstalledCheck
from src.checks.svc_proxy_server import HTTPProxyServerNotInstalledCheck
from src.checks.svc_snmp_server import SNMPServerNotInstalledCheck
from src.checks.svc_postfix import PostfixLocalOnlyCheck
from src.checks.svc_rsync import RsyncNotInstalledCheck
from src.checks.svc_nis_server import NISServerNotInstalledCheck
from src.checks.svc_nis_client import NISClientNotInstalledCheck
from src.checks.svc_rsh_client import RshClientNotInstalledCheck
from src.checks.svc_talk_client import TalkClientNotInstalledCheck
from src.checks.svc_telnet_client import TelnetClientNotInstalledCheck
from src.checks.svc_ldap_client import LDAPClientNotInstalledCheck
from src.checks.svc_rpc_client import RPCClientNotInstalledCheck
# Import Xorg server check (optional for servers)
from src.checks.svc_xorg_server import XorgServerNotInstalledCheck

# Import user/group validation checks (CIS 6.2.x)
from src.checks.user_shadowed_passwords import ShadowedPasswordsCheck
from src.checks.user_no_empty_shadow import NoEmptyShadowPasswordsCheck
from src.checks.user_group_consistency import GroupConsistencyCheck
from src.checks.user_unique_uid import UniqueUIDCheck
from src.checks.user_unique_gid import UniqueGIDCheck
from src.checks.user_unique_name import UniqueUsernameCheck
from src.checks.user_unique_group_name import UniqueGroupNameCheck
from src.checks.user_root_path import RootPathCheck
from src.checks.user_root_only_uid0 import RootOnlyUID0Check
from src.checks.user_home_dirs_exist import HomeDirsExistCheck
from src.checks.user_home_perms import HomePermissionsCheck
from src.checks.user_dotfile_perms import DotfilePermissionsCheck
from src.checks.user_last_password_change import UserLastPasswordChangeCheck
# Import user account security checks (CIS 5.4.x)
from src.checks.user_inactive_lock import InactivePasswordLockCheck
from src.checks.user_system_accounts import SystemAccountsSecuredCheck
from src.checks.user_umask import UserUmaskCheck
from src.checks.user_shell_timeout import ShellTimeoutCheck

__all__ = [
    # Base classes
    "BaseCheck",
    "CheckResult",
    "Severity",
    # Authentication checks
    "PasswordComplexityCheck",
    "AccountLockoutCheck",
    "PasswordExpirationCheck",
    "EmptyPasswordCheck",
    "RootSSHCheck",
    "PasswordReuseCheck",
    "PasswordHashCheck",
    # SSH hardening checks (CIS 5.1.x)
    "SSHConfigPermissionsCheck",
    "SSHProtocolCheck",
    "SSHLogLevelCheck",
    "SSHX11Check",
    "SSHMaxAuthTriesCheck",
    "SSHIgnoreRhostsCheck",
    "SSHHostbasedAuthCheck",
    "SSHPermitEmptyPasswordsCheck",
    "SSHPermitUserEnvCheck",
    "SSHCiphersCheck",
    "SSHIdleTimeoutCheck",
    "SSHLoginGraceTimeCheck",
    # SSH server extras (CIS 5.1.x continued)
    "SSHBannerCheck",
    "SSHPAMEnabledCheck",
    "SSHAllowUsersCheck",
    "SSHDenyUsersCheck",
    "SSHMaxSessionsCheck",
    "SSHCiphersMACCheck",
    "SSHKexCheck",
    "SSHHostKeysPermsCheck",
    # SSH client checks (CIS 5.2.x)
    "SSHClientCiphersCheck",
    "SSHClientMACsCheck",
    "SSHClientKexCheck",
    "SSHClientHostAuthCheck",
    "SSHClientProtocolCheck",
    "SSHClientStrictHostCheck",
    "SSHClientUserEnvCheck",
    # Logging checks
    "RsyslogCheck",
    "AuditdCheck",
    "LogPermissionsCheck",
    "RemoteLoggingCheck",
    "AuditRulesCheck",
    # Journald checks (CIS 4.2.2.x)
    "JournaldRsyslogCheck",
    "JournaldCompressCheck",
    "JournaldPersistentCheck",
    # Logrotate checks (CIS 4.3.x)
    "LogrotateInstalledCheck",
    "LogrotateConfiguredCheck",
    # Cron/at restriction checks (CIS 4.1.x)
    "CronDaemonCheck",
    "CronCrontabPermsCheck",
    "CronHourlyPermsCheck",
    "CronDailyPermsCheck",
    "CronWeeklyPermsCheck",
    "CronMonthlyPermsCheck",
    "CronDPermsCheck",
    "CronRestrictedCheck",
    "AtRestrictedCheck",
    # Audit rule checks (CIS 4.4.x)
    "AuditNetworkChangesCheck",
    "AuditMACChangesCheck",
    "AuditDACChangesCheck",
    "AuditMountsCheck",
    "AuditFileDeletionsCheck",
    "AuditSudoersCheck",
    "AuditSudoLogCheck",
    "AuditKernelModulesCheck",
    "AuditImmutableCheck",
    "AuditGrubCheck",
    "AuditStorageCheck",
    "AuditRetentionCheck",
    # Network checks
    "FirewalldCheck",
    "FirewalldDefaultZoneCheck",
    "IPv6Check",
    "TCPWrappersCheck",
    "NetworkServicesCheck",
    # Network kernel parameter checks (CIS 3.1.x, 3.2.x)
    "IPForwardCheck",
    "PacketRedirectCheck",
    "SourceRoutingCheck",
    "ICMPRedirectsCheck",
    "SecureICMPRedirectsCheck",
    "LogMartiansCheck",
    "IgnoreBroadcastsCheck",
    "IgnoreBogusErrorsCheck",
    "RPFilterCheck",
    "TCPSyncookiesCheck",
    # Uncommon protocol checks (CIS 3.5.x)
    "DCCPProtocolCheck",
    "SCTPProtocolCheck",
    "RDSProtocolCheck",
    "TIPCProtocolCheck",
    # iptables checks (CIS 3.6.x)
    "IPTablesInstalledCheck",
    "IPTablesDefaultDenyCheck",
    "IPTablesLoopbackCheck",
    "IPTablesEstablishedCheck",
    "IPTablesOpenPortsCheck",
    # Time synchronization checks (CIS 2.1.x)
    "TimeSyncEnabledCheck",
    "ChronyConfiguredCheck",
    "TimesyncdConfiguredCheck",
    # NTP server check
    "NTPServerNotInstalledCheck",
    # Filesystem checks
    "TmpMountCheck",
    "VarTmpPermissionsCheck",
    "WorldWritableFilesCheck",
    "SuidSgidAuditCheck",
    "HomePermissionsCheck",
    # Filesystem partition checks (CIS 1.1.x)
    "VarPartitionCheck",
    "VarLogPartitionCheck",
    "VarLogAuditPartitionCheck",
    "HomePartitionCheck",
    "DevShmMountCheck",
    "AutomountDisabledCheck",
    "USBStorageDisabledCheck",
    # Filesystem module checks (CIS 1.1.1.x)
    "CramfsModuleCheck",
    "FreevxfsModuleCheck",
    "Jffs2ModuleCheck",
    "HfsModuleCheck",
    "HfsplusModuleCheck",
    "SquashfsModuleCheck",
    "UdfModuleCheck",
    # AIDE checks (CIS 1.2.x)
    "AIDEInstalledCheck",
    "AIDECronCheck",
    # Boot security checks
    "GrubPasswordCheck",
    "GrubPermissionsCheck",
    "SingleUserAuthCheck",
    # SELinux checks
    "SELinuxInstalledCheck",
    "SELinuxBootloaderCheck",
    "SELinuxPolicyCheck",
    "SELinuxEnforcingCheck",
    "SELinuxUnconfinedCheck",
    "SELinuxSETroubleshootCheck",
    "SELinuxMcstransCheck",
    # AppArmor checks (optional for Fedora)
    "SELinuxAppArmorInstalledCheck",
    "SELinuxAppArmorEnabledCheck",
    # Process hardening checks (CIS 1.4.x)
    "CoreDumpsCheck",
    "ASLRCheck",
    "PrelinkCheck",
    "PtraceCheck",
    # Kernel exec-shield check
    "KernelExecShieldCheck",
    # Warning banner checks (CIS 1.6.x)
    "BannerMotdCheck",
    "BannerIssueCheck",
    "BannerIssueNetCheck",
    "BannerMotdPermsCheck",
    "BannerIssuePermsCheck",
    "BannerIssueNetPermsCheck",
    # GDM settings checks (CIS 1.7.x)
    "GDMBannerCheck",
    "GDMDisableUserListCheck",
    "GDMXDCMPCheck",
    # GDM removal check (optional for servers)
    "GDMRemovedCheck",
    # System file permission checks (CIS 6.1.x)
    "PasswdPermissionsCheck",
    "PasswdBackupPermissionsCheck",
    "GroupPermissionsCheck",
    "GroupBackupPermissionsCheck",
    "ShadowPermissionsCheck",
    "ShadowBackupPermissionsCheck",
    "GshadowPermissionsCheck",
    "GshadowBackupPermissionsCheck",
    "ShellsPermissionsCheck",
    "OpasswdPermissionsCheck",
    # Filesystem unowned/ungrouped checks (expensive scans)
    "FSUnownedFilesCheck",
    "FSUngroupedFilesCheck",
    # Service audit checks (CIS 2.2.x, 2.3.x)
    "XinetdNotInstalledCheck",
    "AvahiNotInstalledCheck",
    "CUPSNotInstalledCheck",
    "DHCPServerNotInstalledCheck",
    "LDAPServerNotInstalledCheck",
    "NFSNotInstalledCheck",
    "DNSServerNotInstalledCheck",
    "FTPServerNotInstalledCheck",
    "HTTPServerNotInstalledCheck",
    "IMAPPO3ServerNotInstalledCheck",
    "SambaNotInstalledCheck",
    "HTTPProxyServerNotInstalledCheck",
    "SNMPServerNotInstalledCheck",
    "PostfixLocalOnlyCheck",
    "RsyncNotInstalledCheck",
    "NISServerNotInstalledCheck",
    "NISClientNotInstalledCheck",
    "RshClientNotInstalledCheck",
    "TalkClientNotInstalledCheck",
    "TelnetClientNotInstalledCheck",
    "LDAPClientNotInstalledCheck",
    "RPCClientNotInstalledCheck",
    # Xorg server check (optional for servers)
    "XorgServerNotInstalledCheck",
    # User/group validation checks (CIS 6.2.x)
    "ShadowedPasswordsCheck",
    "NoEmptyShadowPasswordsCheck",
    "GroupConsistencyCheck",
    "UniqueUIDCheck",
    "UniqueGIDCheck",
    "UniqueUsernameCheck",
    "UniqueGroupNameCheck",
    "RootPathCheck",
    "RootOnlyUID0Check",
    "HomeDirsExistCheck",
    "HomePermissionsCheck",
    "DotfilePermissionsCheck",
    "UserLastPasswordChangeCheck",
    # User account security checks (CIS 5.4.x)
    "InactivePasswordLockCheck",
    "SystemAccountsSecuredCheck",
    "UserUmaskCheck",
    "ShellTimeoutCheck",
]
