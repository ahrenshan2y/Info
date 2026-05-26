#!/usr/bin/env bash
set -u

HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="./ServerAssessment_${HOST}_${TS}"
FINDINGS="$OUT/00_findings.csv"
SUMMARY="$OUT/00_assessment_summary.txt"

mkdir -p "$OUT"
echo "Severity,Category,Details,Evidence" > "$FINDINGS"

add_finding() {
  local sev="$1"; local cat="$2"; local det="$3"; local ev="$4"
  det="$(echo "$det" | sed 's/"/""/g')"
  ev="$(echo "$ev" | sed 's/"/""/g')"
  echo "\"$sev\",\"$cat\",\"$det\",\"$ev\"" >> "$FINDINGS"
}

run_cmd() {
  local name="$1"; shift
  { echo "# Command: $*"; echo "# Time: $(date)"; echo; "$@" 2>&1; } > "$OUT/$name.txt"
}

echo "[*] Read-only assessment started."
echo "[*] Output: $OUT"

if [ "$(id -u)" -ne 0 ]; then
  add_finding "Medium" "Permission Scope" "Running as non-root. Some results may be incomplete." "User: $(id -un)"
fi

run_cmd "01_hostnamectl" hostnamectl
run_cmd "02_uname" uname -a
run_cmd "03_ip_addr" ip addr
run_cmd "04_ip_route" ip route
run_cmd "05_uptime" uptime
run_cmd "06_who" who
[ -f /etc/os-release ] && cp /etc/os-release "$OUT/07_os_release.txt"

if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running --no-pager > "$OUT/08_running_services.txt" 2>&1

  grep -Eqi "mysql|mariadb|postgres|oracle|mongod|redis|mssql" "$OUT/08_running_services.txt" && add_finding "Critical" "Database" "Database service indicator found." "08_running_services.txt"
  grep -Eqi "named|bind9|dnsmasq" "$OUT/08_running_services.txt" && add_finding "Critical" "DNS" "DNS service indicator found." "08_running_services.txt"
  grep -Eqi "isc-dhcp|dhcpd" "$OUT/08_running_services.txt" && add_finding "Critical" "DHCP" "DHCP service indicator found." "08_running_services.txt"
  grep -Eqi "backup|veeam|bacula|rsnapshot|restic|borg|duplicity" "$OUT/08_running_services.txt" && add_finding "Critical" "Backup" "Backup service indicator found." "08_running_services.txt"
  grep -Eqi "docker|containerd|kubelet|k3s" "$OUT/08_running_services.txt" && add_finding "High" "Container" "Container service indicator found." "08_running_services.txt"
  grep -Eqi "nginx|apache2|httpd|tomcat" "$OUT/08_running_services.txt" && add_finding "High" "Web/Application" "Web/application service indicator found." "08_running_services.txt"
  grep -Eqi "smbd|nmbd|nfs-server|rpcbind" "$OUT/08_running_services.txt" && add_finding "High" "File Sharing" "SMB/NFS service indicator found." "08_running_services.txt"
else
  run_cmd "08_services_legacy" service --status-all
fi

if command -v ss >/dev/null 2>&1; then
  ss -tuln > "$OUT/09_listening_ports.txt" 2>&1
  ss -tan state established > "$OUT/10_established_connections.txt" 2>&1

  grep -Eq ":(53)\b" "$OUT/09_listening_ports.txt" && add_finding "Critical" "Listening Port" "DNS port 53 is listening." "09_listening_ports.txt"
  grep -Eq ":(67)\b" "$OUT/09_listening_ports.txt" && add_finding "Critical" "Listening Port" "DHCP port 67 is listening." "09_listening_ports.txt"
  grep -Eq ":(3306|5432|1521|1433|27017|6379)\b" "$OUT/09_listening_ports.txt" && add_finding "Critical" "Listening Port" "Database-related port is listening." "09_listening_ports.txt"
  grep -Eq ":(80|443|8080|8443)\b" "$OUT/09_listening_ports.txt" && add_finding "High" "Listening Port" "Web/application port is listening." "09_listening_ports.txt"
  grep -Eq ":(139|445|2049|111)\b" "$OUT/09_listening_ports.txt" && add_finding "High" "Listening Port" "File-sharing port is listening." "09_listening_ports.txt"

  CONN_COUNT="$(grep -Ev '127.0.0.1|::1|State|Recv-Q' "$OUT/10_established_connections.txt" | wc -l | tr -d ' ')"
  [ "${CONN_COUNT:-0}" -gt 2 ] && add_finding "High" "Active Connections" "Active remote connections detected." "10_established_connections.txt"
else
  run_cmd "09_netstat" netstat -tuln
fi

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

grep -Eqi "/var/lib/mysql|/var/lib/postgresql|/var/lib/mongodb" "$OUT/17_important_directory_sizes.txt" && add_finding "Critical" "Database Data" "Database data directory exists." "17_important_directory_sizes.txt"
grep -Eqi "/backup|/backups" "$OUT/17_important_directory_sizes.txt" && add_finding "High" "Backup Data" "Backup-like directory exists." "17_important_directory_sizes.txt"

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

grep -Eqi "backup|dump|mysqldump|pg_dump|rsync|scp|sftp|ftp|report|sync" "$OUT/18_cron_jobs.txt" && add_finding "High" "Scheduled Jobs" "Backup/sync/report/database scheduled job indicator found." "18_cron_jobs.txt"

if command -v docker >/dev/null 2>&1; then
  docker ps -a > "$OUT/19_docker_containers.txt" 2>&1
  docker volume ls > "$OUT/20_docker_volumes.txt" 2>&1
  docker ps -q 2>/dev/null | grep -q . && add_finding "High" "Docker" "Running Docker containers found." "19_docker_containers.txt"
fi

if command -v virsh >/dev/null 2>&1; then
  virsh list --all > "$OUT/21_virsh_vms.txt" 2>&1
  grep -Eqi "running|shut off" "$OUT/21_virsh_vms.txt" && add_finding "Critical" "Virtualization" "KVM/libvirt virtual machines detected." "21_virsh_vms.txt"
fi

[ -f /etc/exports ] && cp /etc/exports "$OUT/22_nfs_exports.txt"
[ -f /etc/samba/smb.conf ] && cp /etc/samba/smb.conf "$OUT/23_samba_config.txt"

[ -f "$OUT/22_nfs_exports.txt" ] && grep -Evq '^\s*#|^\s*$' "$OUT/22_nfs_exports.txt" && add_finding "High" "NFS" "NFS export configuration found." "22_nfs_exports.txt"
[ -f "$OUT/23_samba_config.txt" ] && grep -Eqi '^\s*\[[^]]+\]' "$OUT/23_samba_config.txt" && add_finding "High" "Samba" "Samba share configuration found." "23_samba_config.txt"

if command -v journalctl >/dev/null 2>&1; then
  journalctl -p err -n 100 --no-pager > "$OUT/24_recent_errors_journalctl.txt" 2>&1
fi

CRITICAL="$(grep -c '^"Critical"' "$FINDINGS" || true)"
HIGH="$(grep -c '^"High"' "$FINDINGS" || true)"
MEDIUM="$(grep -c '^"Medium"' "$FINDINGS" || true)"

if [ "$CRITICAL" -gt 0 ]; then
  REC="DO NOT REMOVE DIRECTLY"
  REASON="Critical indicators were found: database, DNS/DHCP, backup, virtualization, or similar."
elif [ "$HIGH" -ge 3 ]; then
  REC="MIGRATION REQUIRED BEFORE REMOVAL"
  REASON="Multiple important services or dependencies were found."
elif [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ]; then
  REC="POTENTIAL DECOMMISSION CANDIDATE AFTER MANUAL CONFIRMATION"
  REASON="Some indicators were found, or the script ran with limited permission."
else
  REC="LOW-RISK CANDIDATE BUT STILL NEEDS BUSINESS CONFIRMATION"
  REASON="No major indicators were detected within the current permission scope."
fi

cat > "$SUMMARY" <<EOF
Server Decommission Assessment Summary
=====================================

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
Medium:   $MEDIUM

Important:
- This is a read-only local assessment.
- If this script ran as a normal user, the result is incomplete by design.
- Final decommission decision requires customer IT confirmation, backup validation, dependency review, and maintenance-window testing.
EOF

echo
echo "[*] Assessment completed."
echo "[*] Recommendation: $REC"
echo "[*] Report folder: $OUT"
