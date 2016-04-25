# == Class: osd_secure
#
# Full description of class osd_secure here.
#
# === Parameters
#
# Document parameters here.
#
# [*sample_parameter*]
#   Explanation of what this parameter affects and what it defaults to.
#   e.g. "Specify one or more upstream ntp servers as an array."
#
# === Variables
#
# Here you should define a list of variables that this module would require.
#
# [*sample_variable*]
#   Explanation of how this variable affects the funtion of this class and if
#   it has a default. e.g. "The parameter enc_ntp_servers must be set by the
#   External Node Classifier as a comma separated list of hostnames." (Note,
#   global variables should be avoided in favor of class parameters as
#   of Puppet 2.6.)
#
# === Examples
#
#  class { 'osd_secure':
#    servers => [ 'pool.ntp.org', 'ntp.local.company.com' ],
#  }
#
# === Authors
#
# Author Name <author@domain.com>
#
# === Copyright
#
# Copyright 2016 Your name here, unless otherwise noted.
#
class osd_secure {

  # xccdf_org.ssgproject.content_rule_ensure_redhat_gpgkey_installed
  define rhkey ($source="https://www.redhat.com/security/${title}.txt") {
    exec { "install rh key $title":
      command => "/bin/rpm --import $source",
      unless  => "/bin/rpm -q gpg-pubkey-${title}",
    } 
  }
  osd_secure::rhkey {
    'fd431d51': ;
    '37017186': ;
    'db42a60e': ;
    '8366b0d9': ;
    '2fa658e0': source => 'https://gist.githubusercontent.com/asquelt/b1123960258c8f319ae1ccc62f3c10ce/raw/79a54dbeb39c07a37febf59b1958d9b56ceb6b99/2fa658e0.pem' ;
  }

  # xccdf_org.ssgproject.content_rule_ensure_gpgcheck_never_disabled
  exec { 'gpgcheck_enable_foreman_repo':
    command => '/bin/sed -i -e "s/gpgcheck=0/gpgcheck=1/" /etc/yum.repos.d/foreman-plugins.repo',
    onlyif  => '/bin/grep gpgcheck=0 /etc/yum.repos.d/foreman-plugins.repo',
  }

  # xccdf_org.ssgproject.content_rule_disable_prelink
  package { 'prelink':
    ensure  => 'installed',
  } ->
  file { '/etc/sysconfig/prelink':
    ensure  => 'file',
    content => "\n# Set PRELINKING=no per security requirements\nPRELINKING=no\n\n",
    notify  => Exec['disable_prelink'],
  }
  exec { 'disable_prelink':
    command     => '/sbin/prelink -ua',
    refreshonly => true,
  }

  # xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit
  file { '/etc/security/pwquality.conf':
    ensure  => file,
    content => "
minlen = 16
dcredit = -2
ucredit = -2
lcredit = -2
";
  }

  # xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_libuserconf
  file_line { 'crypt_shadow_with_sha512':
    path  => '/etc/libuser.conf',
    line  => 'crypt_style = sha512',
    match => '^crypt_style\ =',
  }

  # xccdf_org.ssgproject.content_rule_package_libreswan_installed
  package { 'libreswan':
    ensure => installed,
  }

  # xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex
  file { '/etc/audit/rules.d/pcidss.rules':
    ensure  => file,
    content => "
-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

-a always,exit -F arch=b32 -S stime -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

-w /etc/localtime -p wa -k audit_time_rules

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k export

-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k actions

-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
";
  }

  # xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated
  file_line { 'audit_to_syslog':
    path  => '/etc/audisp/plugins.d/syslog.conf',
    line  => 'active = yes',
    match => '^active\ =',
  }

  # xccdf_org.ssgproject.content_rule_service_chronyd_or_ntpd_enabled
  package { 'chrony':
    ensure => installed,
  } ->
  service { 'chronyd':
    ensure => running,
    enable => true,
  }

  # xccdf_org.ssgproject.content_rule_bootloader_audit_argument
  exec { 'enable_boot_audit':
    command => '/bin/sed -i "s/\(GRUB_CMDLINE_LINUX=\)\"\(.*\)\"/\1\"\2 audit=1\"/" /etc/default/grub',
    unless  => '/bin/grep GRUB_CMDLINE_LINUX=.*audit=1 /etc/default/grub',
    notify  => Exec['update_grubby'],
  }
  exec { 'update_grubby':
    command     => '/sbin/grubby --update-kernel=ALL --args="audit=1"',
    refreshonly => true,
  }

  # xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny
  file { '/etc/pam.d/password-auth':
    ensure  => file,
    content => '#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent deny=6 unlock_time=1800 fail_interval=900
auth        sufficient    pam_unix.so nullok try_first_pass
auth        [default=die] pam_faillock.so authfail deny=6 unlock_time=1800 fail_interval=900
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
',
  }
}
