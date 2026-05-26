#!/usr/bin/env bash
set -u

HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="./ServerAssessment_${HOST}_${TS}"
FINDINGS="$OUT/00_findings.csv"
SUMMARY="$OUT/00_assessment_summary.txt"

mkdir -p "$OUT"
echo "Severity,Category,Details,Evidence,Validation" > "$FINDINGS"

add_finding() {
  local sev="$1"; local cat="$2"; local det="$3"; local ev="$4"; local val="$5"
  det="$(echo "$det" | sed 's/"/""/g')"
  ev="$(echo "$ev" | sed 's/"/""/g')"
  val="$(echo "$val" | sed 's/"/""/g')"
  echo "\"$sev\",\"$cat\",\"$det\",\"$ev\",\"$val\"" >> "$FINDINGS"
}

run_cmd() {
  local name="$1"; shift
  { echo "# Command: $*"; echo "# Time: $(date)"; echo; "$@" 2>&1; } > "$OUT/$name.txt"
}

has_non_loopback_port() {
  local port="$1"
  [ -f "$OUT/09_listening_ports.txt" ] || return 1
  grep -E "[:.]${port}\b" "$OUT/09_listening_ports.txt" | grep -Evq "127\.|::1|127\.0\.0\.53|localhost"
}

has_non_loopback_any_port() {
  local ports="$1"
  [ -f "$OUT/09_listening_ports.txt" ] || return 1
  grep -E "[:.](${ports})\b" "$OUT/09_listening_ports.txt" | grep -Evq "127\.|::1|127\.0\.0\.53|localhost"
}

echo "[*] Read-only assessment v2 started."
echo "[*] Output: $OUT"

if [ "$(id -u)" -ne 0 ]; then
  add_finding "Review" "Permission Scope" "Running as non-root. Some results may be incomplete." "User: $(id -un)" "Use sudo/customer IT confirmation for final decision."
fi

# Basic information
run_cmd "01_hostnamectl" hostnamectl
run_cmd "02_uname" uname -a
run_cmd "03_ip_addr" ip addr
run_cmd "04_ip_route" ip route
run_cmd "05_uptime" uptime
run_cmd "06_who" who
[ -f /etc/os-release ] && cp /etc/os-release "$OUT/07_os_release.txt"

# Virtualization environment: info only
if command -v systemd-detect-virt >/dev/null 2>&1; then
  systemd-detect-virt > "$OUT/08_virtualization_environment.txt" 2>&1 || true
  VIRT_ENV="$(cat "$OUT/08_virtualization_environment.txt" 2>/dev/null | head -1)"
  if [ -n "$VIRT_ENV" ] && [ "$VIRT_ENV" != "none" ]; then
    add_finding "Info" "Virtualization Environment" "Host appears to run inside virtualized/containerized environment: $VIRT_ENV" "08_virtualization_environment.txt" "This does not mean this host is a virtualization server."
  fi
fi

# Services
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running --no-pager > "$OUT/09_running_services.txt" 2>&1
else
  run_cmd "09_running_services_legacy" service --status-all
fi

# Ports and active connections
if command -v ss >/dev/null 2>&1; then
  ss -tuln > "$OUT/09_listening_ports.txt" 2>&1
  ss -tan state established > "$OUT/10_established_connections.txt" 2>&1
else
  run_cmd "09_listening_ports" netstat -tuln
  run_cmd "10_established_connections" netstat -tan
fi

# DNS: distinguish local resolver from real DNS service
if grep -Eqi "systemd-resolved" "$OUT/09_running_services.txt" 2>/dev/null && grep -Eq "127\.0\.0\.53|127\.0\.0\.1|::1" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  add_finding "Info" "DNS" "Local DNS resolver detected, likely systemd-resolved." "09_running_services.txt;09_listening_ports.txt" "Local resolver/cache. Not an enterprise DNS server by itself."
fi

if grep -Eqi "named|bind9|dnsmasq" "$OUT/09_running_services.txt" 2>/dev/null || grep -Eq "[:.]53\b" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  if has_non_loopback_port 53; then
    add_finding "Critical" "DNS" "DNS appears to listen on non-loopback address." "09_listening_ports.txt" "Could serve other clients. Confirm DNS dependency before decommission."
  else
    add_finding "Info" "DNS" "DNS listener appears loopback/local-only." "09_listening_ports.txt" "Likely local resolver/cache. Not enough for critical classification."
  fi
fi

# DHCP
if grep -Eqi "isc-dhcp|dhcpd" "$OUT/09_running_services.txt" 2>/dev/null || grep -Eq "[:.]67\b" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  if has_non_loopback_port 67; then
    add_finding "Critical" "DHCP" "DHCP appears to listen on non-loopback address." "09_listening_ports.txt" "Could provide client IP leases. Confirm DHCP scopes."
  else
    add_finding "Review" "DHCP" "DHCP-related indicator appears local-only or inconclusive." "09_listening_ports.txt" "Validate manually."
  fi
fi

# Database
if grep -Eqi "mysql|mariadb|postgres|oracle|mongod|redis|mssql" "$OUT/09_running_services.txt" 2>/dev/null || grep -Eq "[:.](3306|5432|1521|1433|27017|6379)\b" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  if has_non_loopback_any_port "3306|5432|1521|1433|27017|6379"; then
    add_finding "Critical" "Database" "Database appears to listen on non-loopback address." "09_running_services.txt;09_listening_ports.txt" "Likely application dependency. Confirm DB owner, clients, and backup."
  else
    add_finding "High" "Database" "Database indicator found but appears local-only or incomplete." "09_running_services.txt;09_listening_ports.txt" "Confirm whether local applications depend on it."
  fi
fi

# Web/Application
if grep -Eqi "nginx|apache2|httpd|tomcat" "$OUT/09_running_services.txt" 2>/dev/null || grep -Eq "[:.](80|443|8080|8443)\b" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  if has_non_loopback_any_port "80|443|8080|8443"; then
    add_finding "High" "Web/Application" "Web/application service appears to listen on non-loopback address." "09_running_services.txt;09_listening_ports.txt" "Confirm business owner, URL/DNS, and application dependency."
  else
    add_finding "Review" "Web/Application" "Web/application indicator appears local-only." "09_listening_ports.txt" "May be local admin/dev service."
  fi
fi

# File sharing
if grep -Eqi "smbd|nmbd|nfs-server|rpcbind" "$OUT/09_running_services.txt" 2>/dev/null || grep -Eq "[:.](139|445|2049|111)\b" "$OUT/09_listening_ports.txt" 2>/dev/null; then
  if has_non_loopback_any_port "139|445|2049|111"; then
    add_finding "High" "File Sharing" "SMB/NFS service appears to listen on non-loopback address." "09_running_services.txt;09_listening_ports.txt" "Confirm shared folders, users, permissions, and migration."
  else
    add_finding "Review" "File Sharing" "File-sharing indicator appears local-only or inconclusive." "09_listening_ports.txt" "Validate manually."
  fi
fi

# Backup indicators
if grep -Eqi "backup|veeam|bacula|rsnapshot|restic|borg|duplicity" "$OUT/09_running_services.txt" 2>/dev/null; then
  add_finding "Critical" "Backup" "Backup-related service indicator found." "09_running_services.txt" "Confirm backup repository, retention, and restore dependency."
fi

# Docker: only running containers matter
if command -v docker >/dev/null 2>&1; then
  docker ps -a > "$OUT/19_docker_containers.txt" 2>&1
  docker volume ls > "$OUT/20_docker_volumes.txt" 2>&1
  RUNNING_DOCKER="$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
  ALL_DOCKER="$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${RUNNING_DOCKER:-0}" -gt 0 ]; then
    add_finding "High" "Docker" "Running Docker containers found." "19_docker_containers.txt" "Inspect containers to identify business workload."
  elif [ "${ALL_DOCKER:-0}" -gt 0 ]; then
    add_finding "Review" "Docker" "Docker installed and stopped containers exist." "19_docker_containers.txt" "Not necessarily active workload."
  else
    add_finding "Info" "Docker" "Docker installed but no containers detected." "19_docker_containers.txt" "Framework only; not a workload by itself."
  fi
fi

# KVM/libvirt: only real VMs matter
if command -v virsh >/dev/null 2>&1; then
  virsh list --all > "$OUT/21_virsh_vms.txt" 2>&1
  if grep -Eqi "running|shut off|paused" "$OUT/21_virsh_vms.txt"; then
    add_finding "Critical" "Virtualization Host" "KVM/libvirt virtual machines detected." "21_virsh_vms.txt" "Likely VM host. Confirm VM roles before decommission."
  else
    add_finding "Info" "Virtualization Tooling" "virsh/libvirt tooling found but no VM listed." "21_virsh_vms.txt" "Tooling alone is not a VM host indicator."
  fi
fi

# Resources and directories
run_cmd "11_top_processes_memory" sh -c "ps aux --sort=-%mem | head -30"
run_cmd "12_top_processes_cpu" sh -c "ps aux --sort=-%cpu | head -30"
run_cmd "13_df_h" df -h
run_cmd "14_lsblk" lsblk
run_cmd "15_free_h" free -h
run_cmd "16_mount" mount

{
  echo "# Important directory sizes"
  for p in /data /backup /backups /srv /var/www /var/lib/mysql /var/lib/postgresql /var/lib/mongodb /opt /home; do
    if [ -e "$p" ]; then
      echo; echo "## $p"
      timeout 60 du -sh "$p" 2>/dev/null || echo "Permission denied or timeout."
    fi
  done
} > "$OUT/17_important_directory_sizes.txt"

grep -Eqi "/var/lib/mysql|/var/lib/postgresql|/var/lib/mongodb" "$OUT/17_important_directory_sizes.txt" && \
  add_finding "High" "Database Data" "Database-like data directory exists." "17_important_directory_sizes.txt" "Directory presence alone requires service/application validation."

grep -Eqi "/backup|/backups" "$OUT/17_important_directory_sizes.txt" && \
  add_finding "High" "Backup Data" "Backup-like directory exists." "17_important_directory_sizes.txt" "Confirm if active backup repository or old data."

# Cron jobs
{
  echo "# Current user crontab"
  crontab -l 2>&1
  echo
  echo "# /etc/crontab"
  [ -f /etc/crontab ] && cat /etc/crontab
  echo
  echo "# /etc/cron*"
  ls -la /etc/cron* 2>&1
} > "$OUT/18_cron_jobs.txt"

grep -Eqi "backup|dump|mysqldump|pg_dump|rsync|scp|sftp|ftp|report|sync" "$OUT/18_cron_jobs.txt" && \
  add_finding "High" "Scheduled Jobs" "Backup/sync/report/database scheduled job indicator found." "18_cron_jobs.txt" "Validate whether task is active and business-critical."

# Active remote connections
if [ -f "$OUT/10_established_connections.txt" ] && grep -Ev '127\.|::1|State|Recv-Q|Address|localhost' "$OUT/10_established_connections.txt" | grep -q .; then
  add_finding "Review" "Active Connections" "Remote established connections detected." "10_established_connections.txt" "Check peer IPs and application owners."
fi

# File sharing configs
[ -f /etc/exports ] && cp /etc/exports "$OUT/22_nfs_exports.txt"
[ -f /etc/samba/smb.conf ] && cp /etc/samba/smb.conf "$OUT/23_samba_config.txt"

[ -f "$OUT/22_nfs_exports.txt" ] && grep -Evq '^\s*#|^\s*$' "$OUT/22_nfs_exports.txt" && \
  add_finding "High" "NFS" "NFS export configuration found." "22_nfs_exports.txt" "Confirm if shares are used."

[ -f "$OUT/23_samba_config.txt" ] && grep -Eqi '^\s*\[[^]]+\]' "$OUT/23_samba_config.txt" && \
  add_finding "High" "Samba" "Samba share configuration found." "23_samba_config.txt" "Confirm if shares are used."

# Logs
if command -v journalctl >/dev/null 2>&1; then
  journalctl -p err -n 100 --no-pager > "$OUT/24_recent_errors_journalctl.txt" 2>&1
fi

CRITICAL="$(grep -c '^"Critical"' "$FINDINGS" || true)"
HIGH="$(grep -c '^"High"' "$FINDINGS" || true)"
REVIEW="$(grep -c '^"Review"' "$FINDINGS" || true)"
INFO="$(grep -c '^"Info"' "$FINDINGS" || true)"

if [ "$CRITICAL" -gt 0 ]; then
  REC="DO NOT REMOVE DIRECTLY"
  REASON="Validated critical indicators were found, such as externally listening DNS/DHCP/database, backup service, or actual VM host."
elif [ "$HIGH" -gt 0 ]; then
  REC="MIGRATION OR OWNER VALIDATION REQUIRED BEFORE REMOVAL"
  REASON="Important service indicators were found, but they need owner/dependency validation."
elif [ "$REVIEW" -gt 0 ]; then
  REC="REQUIRES MANUAL VALIDATION"
  REASON="Only review-level or limited-permission indicators were found."
else
  REC="LOW-RISK CANDIDATE BUT STILL NEEDS BUSINESS CONFIRMATION"
  REASON="No critical/high indicators were detected within the current permission scope."
fi

cat > "$SUMMARY" <<EOF
Server Decommission Assessment Summary v2
========================================

Server: $HOST
Timestamp: $TS
Output Directory: $OUT

Preliminary Recommendation:
$REC

Reason:
$REASON

Finding Counts:
Critical: $CRITICAL
High:     $HIGH
Review:   $REVIEW
Info:     $INFO

Interpretation:
- Critical: Do not remove directly. Validate and migrate first.
- High: Possible business/service dependency. Confirm owner and migration requirement.
- Review: Needs manual validation; not enough for critical classification.
- Info: Local-only or environmental information, usually not blocking by itself.

Important:
- This is a read-only local assessment.
- Local DNS resolver, WSL, Docker tooling, or virtualization environment are not automatically treated as enterprise services.
- If this script ran as a normal user, the result is incomplete by design.
- Final decommission decision requires customer IT confirmation, backup validation, dependency review, and maintenance-window testing.
EOF

echo
echo "[*] Assessment completed."
echo "[*] Recommendation: $REC"
echo "[*] Report folder: $OUT"
