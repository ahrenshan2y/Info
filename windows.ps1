param(
    [string]$OutputRoot = ".\ServerAssessment"
)

$ErrorActionPreference = "Continue"

$ComputerName = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $OutputRoot "$ComputerName`_$Timestamp"
$RawDir = Join-Path $OutputDir "raw"
$FindingsPath = Join-Path $OutputDir "00_findings.csv"
$ReportPath = Join-Path $OutputDir "server_assessment_report.txt"

New-Item -ItemType Directory -Path $RawDir -Force | Out-Null

$Findings = New-Object System.Collections.Generic.List[Object]

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Details,
        [string]$Evidence,
        [string]$Validation
    )

    $Findings.Add([PSCustomObject]@{
        Severity   = $Severity
        Category   = $Category
        Details    = $Details
        Evidence   = $Evidence
        Validation = $Validation
    })
}

function Save-Text {
    param([string]$Name, [scriptblock]$Command)
    try {
        & $Command | Out-File -FilePath (Join-Path $RawDir "$Name.txt") -Encoding UTF8
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $RawDir "$Name.txt") -Encoding UTF8
    }
}

function Save-Csv {
    param([string]$Name, [scriptblock]$Command)
    try {
        & $Command | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "$Name.csv")
    }
    catch {
        [PSCustomObject]@{ Error = $_.Exception.Message } |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "$Name.csv")
    }
}

function Add-ReportSection {
    param([string]$Title, [string]$Path)
    Add-Content -Path $ReportPath -Value ""
    Add-Content -Path $ReportPath -Value "================================================================"
    Add-Content -Path $ReportPath -Value $Title
    Add-Content -Path $ReportPath -Value "================================================================"
    if (Test-Path $Path) {
        Get-Content $Path -ErrorAction SilentlyContinue | Add-Content -Path $ReportPath
    }
    else {
        Add-Content -Path $ReportPath -Value "Not collected or not available."
    }
}

function Test-NonLoopbackListenPort {
    param([int[]]$Ports)

    $matches = $Global:TcpConnections | Where-Object {
        $_.State -eq "Listen" -and
        $Ports -contains [int]$_.LocalPort -and
        $_.LocalAddress -notin @("127.0.0.1", "::1", "localhost") -and
        $_.LocalAddress -notmatch "^169\.254\."
    }

    return (($matches | Measure-Object).Count -gt 0)
}

Write-Host "[*] Read-only Windows single-report assessment started."
Write-Host "[*] Output directory: $OutputDir"

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Add-Finding "Review" "Permission Scope" "Running as non-administrator. Some results may be incomplete." $identity.Name "Use local admin/customer IT confirmation for final decommission decision."
    }
}
catch {
    Add-Finding "Review" "Permission Scope" "Unable to determine administrator status." $_.Exception.Message "Validate permission scope manually."
}

# Basic collection
Save-Text "01_hostname" { hostname }
Save-Text "02_systeminfo" { systeminfo }
Save-Text "03_ipconfig_all" { ipconfig /all }
Save-Text "04_route_print" { route print }

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem

    [PSCustomObject]@{
        ComputerName = $cs.Name
        Domain       = $cs.Domain
        DomainRole   = $cs.DomainRole
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        TotalRAM_GB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        OS           = $os.Caption
        Version      = $os.Version
        LastBootTime = $os.LastBootUpTime
        HypervisorPresent = $cs.HypervisorPresent
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "05_computer_summary.csv")

    if ($cs.DomainRole -in 4,5) {
        Add-Finding "Critical" "Domain Controller" "This Windows host appears to be a Domain Controller." "05_computer_summary.csv" "Do not remove directly. Confirm AD FSMO roles, replication, DNS, and demotion plan."
    }

    if ($cs.HypervisorPresent -eq $true) {
        Add-Finding "Info" "Virtualization Environment" "Hypervisor is present or the host may be virtualized." "05_computer_summary.csv" "This alone does not mean the server is hosting production VMs."
    }
}
catch {
    Add-Finding "Review" "System Info" "Failed to collect complete computer details." $_.Exception.Message "Validate manually."
}

# Features
try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $features = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"}
        $features | Select-Object Name, DisplayName, InstallState |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "06_installed_windows_features.csv")

        foreach ($f in $features) {
            switch ($f.Name) {
                "AD-Domain-Services" { Add-Finding "Critical" "Installed Role" "Active Directory Domain Services role installed." $f.Name "Confirm if this is an active DC before decommission." }
                "DNS" { Add-Finding "High" "Installed Role" "DNS Server role installed." $f.Name "Validate whether DNS service is active and clients use it." }
                "DHCP" { Add-Finding "High" "Installed Role" "DHCP Server role installed." $f.Name "Validate active scopes and leases." }
                "Hyper-V" { Add-Finding "Review" "Installed Role" "Hyper-V role installed." $f.Name "Role installed does not prove active VM workload. Check Get-VM result." }
                "Failover-Clustering" { Add-Finding "Critical" "Installed Role" "Failover Clustering role installed." $f.Name "Confirm cluster membership and workloads." }
                "File-Services" { Add-Finding "Review" "Installed Role" "File Services role installed." $f.Name "Validate SMB shares and users." }
                "Web-Server" { Add-Finding "Review" "Installed Role" "IIS Web Server role installed." $f.Name "Validate active websites and bindings." }
                "Windows-Server-Backup" { Add-Finding "High" "Installed Role" "Windows Server Backup feature installed." $f.Name "Validate active backup jobs/repository." }
            }
        }
    }
    else {
        Add-Finding "Info" "Windows Feature" "Get-WindowsFeature is unavailable." "Possible client OS or missing module." "Cannot infer server roles from this command."
    }
}
catch {
    Add-Finding "Review" "Windows Feature" "Failed to collect Windows features." $_.Exception.Message "Validate roles manually."
}

# Services
Save-Csv "07_running_services" {
    Get-CimInstance Win32_Service |
        Where-Object {$_.State -eq "Running"} |
        Select-Object Name, DisplayName, State, StartMode, PathName
}

try {
    $services = Get-CimInstance Win32_Service | Where-Object {$_.State -eq "Running"}
    $serviceText = ($services | ForEach-Object { "$($_.Name) $($_.DisplayName)" }) -join "`n"

    if ($serviceText -match "NTDS") { Add-Finding "Critical" "AD Service" "Active Directory Domain Services indicator detected." "07_running_services.csv" "Confirm DC role." }
    if ($serviceText -match "DHCPServer") { Add-Finding "High" "DHCP Service" "DHCP Server service is running." "07_running_services.csv" "Confirm active scopes and client dependencies." }
    if ($serviceText -match "\bDNS\b|DNS Server") { Add-Finding "High" "DNS Service" "DNS Server service indicator detected." "07_running_services.csv" "Confirm client DNS dependency." }
    if ($serviceText -match "MSSQL|SQLSERVERAGENT|MySQL|MariaDB|PostgreSQL|OracleService") { Add-Finding "High" "Database Service" "Database service indicator detected." "07_running_services.csv" "Confirm application dependency and backup." }
    if ($serviceText -match "Veeam|Acronis|Backup Exec|Windows Server Backup") { Add-Finding "Critical" "Backup Service" "Backup-related service indicator detected." "07_running_services.csv" "Confirm backup repository, retention, restore dependency." }
    if ($serviceText -match "vmms|Hyper-V Virtual Machine Management") { Add-Finding "Review" "Hyper-V Service" "Hyper-V management service is running." "07_running_services.csv" "Check whether VMs exist/running." }
    if ($serviceText -match "W3SVC|IIS|Apache|Nginx|Tomcat") { Add-Finding "Review" "Web/Application Service" "Web/application service indicator detected." "07_running_services.csv" "Confirm active sites and business owner." }
    if ($serviceText -match "Splunk|Zabbix|PRTG|Datadog|Telegraf|Monitoring") { Add-Finding "High" "Monitoring/Logging" "Monitoring/logging service indicator detected." "07_running_services.csv" "Confirm infrastructure dependency." }
    if ($serviceText -match "License|FlexNet|Sentinel") { Add-Finding "High" "License Service" "License service indicator detected." "07_running_services.csv" "Confirm application dependency." }
}
catch {
    Add-Finding "Review" "Running Service" "Failed to analyze running services." $_.Exception.Message "Validate manually."
}

# Installed software
try {
    $paths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $programs = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object {$_.DisplayName} |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }

    $programs | Sort-Object DisplayName -Unique |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "08_installed_software.csv")

    foreach ($p in $programs) {
        if ($p.DisplayName -match "SQL Server|MySQL|MariaDB|PostgreSQL|Oracle|Veeam|Acronis|Backup|VMware|Hyper-V|Splunk|Zabbix|PRTG|License|FlexNet|Sentinel|ERP|WMS|CRM") {
            Add-Finding "Review" "Installed Software" "Business/infrastructure software indicator found: $($p.DisplayName)" $p.DisplayName "Installed software alone does not prove active dependency."
        }
    }
}
catch {
    Add-Finding "Review" "Installed Software" "Failed to collect installed software." $_.Exception.Message "Validate manually."
}

# Network
$Global:TcpConnections = @()
try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

        $Global:TcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object {$_.State -in @("Listen","Established")} |
            ForEach-Object {
                [PSCustomObject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    State         = $_.State
                    ProcessId     = $_.OwningProcess
                    ProcessName   = $procMap[$_.OwningProcess]
                }
            }

        $Global:TcpConnections | Sort-Object State, LocalPort |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "09_tcp_connections.csv")

        if (Test-NonLoopbackListenPort @(53)) { Add-Finding "Critical" "Listening Port" "DNS port 53 listens on non-loopback address." "09_tcp_connections.csv" "Confirm DNS dependency." }
        if (Test-NonLoopbackListenPort @(67)) { Add-Finding "Critical" "Listening Port" "DHCP port 67 listens on non-loopback address." "09_tcp_connections.csv" "Confirm DHCP scopes." }
        if (Test-NonLoopbackListenPort @(88,389,636)) { Add-Finding "Critical" "Listening Port" "Kerberos/LDAP port listens on non-loopback address." "09_tcp_connections.csv" "Possible AD/directory dependency." }
        if (Test-NonLoopbackListenPort @(1433,1521,3306,5432)) { Add-Finding "Critical" "Database Port" "Database port listens on non-loopback address." "09_tcp_connections.csv" "Confirm clients and backup." }
        if (Test-NonLoopbackListenPort @(80,443,8080,8443)) { Add-Finding "High" "Web/Application Port" "Web/application port listens on non-loopback address." "09_tcp_connections.csv" "Confirm URL/DNS/business owner." }
        if (Test-NonLoopbackListenPort @(445,139)) { Add-Finding "High" "SMB/File Sharing Port" "SMB port listens on non-loopback address." "09_tcp_connections.csv" "Confirm SMB shares and users." }

        $activeRemote = $Global:TcpConnections | Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -notin @("127.0.0.1","::1","0.0.0.0","::","localhost")
        }

        if (($activeRemote | Measure-Object).Count -gt 0) {
            Add-Finding "Review" "Active Connections" "Remote established connections detected." "09_tcp_connections.csv" "Check peer IPs and application owners."
        }
    }
    else {
        Save-Text "09_netstat_ano" { netstat -ano }
        Add-Finding "Review" "Network" "Get-NetTCPConnection unavailable; netstat collected instead." "09_netstat_ano.txt" "Analyze manually."
    }
}
catch {
    Add-Finding "Review" "Network" "Failed to collect TCP connection information." $_.Exception.Message "Validate manually."
}

# SMB
try {
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        $shares | Select-Object Name, Path, Description, ShareState, ShareType |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "10_smb_shares.csv")

        $userShares = $shares | Where-Object { $_.Name -notmatch "^[A-Z]\$$" -and $_.Name -notin @("ADMIN$","IPC$","print$") }
        if (($userShares | Measure-Object).Count -gt 0) {
            Add-Finding "High" "File Sharing" "Non-default SMB shares found." "10_smb_shares.csv" "Confirm share users, permissions, owner, migration."
        }
    }
}
catch {
    Add-Finding "Review" "SMB" "Failed to collect SMB share information." $_.Exception.Message "Validate manually."
}

# Scheduled tasks
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Disabled"}
    $taskReport = foreach ($t in $tasks) {
        [PSCustomObject]@{
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State    = $t.State
            Actions  = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " ; "
        }
    }
    $taskReport | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "11_scheduled_tasks.csv")

    $interesting = $taskReport | Where-Object {
        $_.TaskName -match "backup|sync|sql|mysql|dump|report|ftp|sftp|robocopy|copy|veeam|acronis" -or
        $_.Actions -match "backup|sync|sql|mysql|dump|report|ftp|sftp|robocopy|copy|veeam|acronis"
    }
    if (($interesting | Measure-Object).Count -gt 0) {
        Add-Finding "High" "Scheduled Tasks" "Backup/sync/report/database scheduled task indicator found." "11_scheduled_tasks.csv" "Validate active/business-critical status."
    }
}
catch {
    Add-Finding "Review" "Scheduled Tasks" "Failed to collect scheduled tasks." $_.Exception.Message "Validate manually."
}

# Disk/processes
Save-Csv "12_volumes" { Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, SizeRemaining, Size }
Save-Csv "13_disks" { Get-Disk | Select-Object Number, FriendlyName, SerialNumber, HealthStatus, OperationalStatus, Size, PartitionStyle }
Save-Csv "14_processes_top_cpu" { Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name, Id, CPU, WorkingSet, Path }
Save-Csv "15_processes_top_memory" { Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 30 Name, Id, CPU, WorkingSet, Path }

# Hyper-V
try {
    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
        $vms = Get-VM -ErrorAction SilentlyContinue
        $vms | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime, Status |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "16_hyperv_vms.csv")

        $runningVms = $vms | Where-Object {$_.State -eq "Running"}
        if (($runningVms | Measure-Object).Count -gt 0) {
            Add-Finding "Critical" "Virtualization Host" "Running Hyper-V virtual machines detected." "16_hyperv_vms.csv" "Do not remove directly. Confirm VM roles and migrate first."
        }
        elseif (($vms | Measure-Object).Count -gt 0) {
            Add-Finding "High" "Virtualization Host" "Hyper-V virtual machines exist but are not running." "16_hyperv_vms.csv" "Confirm whether old, standby, or required VMs."
        }
        else {
            Add-Finding "Info" "Hyper-V" "Hyper-V module available but no VMs detected." "16_hyperv_vms.csv" "Tooling/role alone is not active workload."
        }
    }
}
catch {
    Add-Finding "Review" "Hyper-V" "Failed to collect Hyper-V VM information." $_.Exception.Message "May require local admin rights."
}

# Event logs
try {
    Get-WinEvent -FilterHashtable @{LogName="System"; Level=2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "17_system_errors_last_7_days.csv")

    Get-WinEvent -FilterHashtable @{LogName="Application"; Level=2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $RawDir "18_application_errors_last_7_days.csv")
}
catch {
    Add-Finding "Review" "Event Logs" "Failed to collect event log errors." $_.Exception.Message "May require additional permissions."
}

# Save findings
$Findings | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $FindingsPath

$critical = ($Findings | Where-Object {$_.Severity -eq "Critical"} | Measure-Object).Count
$high     = ($Findings | Where-Object {$_.Severity -eq "High"} | Measure-Object).Count
$review   = ($Findings | Where-Object {$_.Severity -eq "Review"} | Measure-Object).Count
$info     = ($Findings | Where-Object {$_.Severity -eq "Info"} | Measure-Object).Count

if ($critical -gt 0) {
    $rec = "DO NOT REMOVE DIRECTLY"
    $reason = "Validated critical indicators were found, such as AD/DC, externally listening DNS/DHCP/database, backup service, clustering, or actual VM workload."
}
elseif ($high -gt 0) {
    $rec = "MIGRATION OR OWNER VALIDATION REQUIRED BEFORE REMOVAL"
    $reason = "Important service indicators were found, but owner/dependency validation is required."
}
elseif ($review -gt 0) {
    $rec = "REQUIRES MANUAL VALIDATION"
    $reason = "Only review-level or limited-permission indicators were found."
}
else {
    $rec = "LOW-RISK CANDIDATE BUT STILL NEEDS BUSINESS CONFIRMATION"
    $reason = "No critical/high indicators were detected within the current permission scope."
}

# Build single report
@"
Server Decommission Assessment Report - Windows v3
==================================================

Server: $ComputerName
Timestamp: $Timestamp
Report Directory: $OutputDir

Preliminary Recommendation:
$rec

Reason:
$reason

Finding Counts:
Critical: $critical
High:     $high
Review:   $review
Info:     $info

Meaning:
- Critical: Do not remove directly. Validate and migrate first.
- High: Possible business/service dependency. Confirm owner and migration requirement.
- Review: Needs manual validation; not enough for critical classification.
- Info: Local-only or environmental information, usually not blocking by itself.

Important:
- This is a read-only local assessment.
- Installed roles/tools alone are not automatically treated as active business workloads.
- HypervisorPresent or Hyper-V role alone does not mean this server is hosting production VMs.
- If this script ran as normal user, the result is incomplete by design.
- Final decommission decision requires customer IT confirmation, backup validation, dependency review, and maintenance-window testing.

"@ | Out-File -FilePath $ReportPath -Encoding UTF8

Add-ReportSection "FINDINGS - ALL DETAILS" $FindingsPath

foreach ($sev in @("Critical","High","Review","Info")) {
    Add-Content -Path $ReportPath -Value ""
    Add-Content -Path $ReportPath -Value "================================================================"
    Add-Content -Path $ReportPath -Value "FINDINGS - $sev"
    Add-Content -Path $ReportPath -Value "================================================================"
    $rows = $Findings | Where-Object {$_.Severity -eq $sev}
    if (($rows | Measure-Object).Count -gt 0) {
        $rows | Format-List | Out-String | Add-Content -Path $ReportPath
    }
    else {
        Add-Content -Path $ReportPath -Value "None"
    }
}

Add-ReportSection "BASIC - hostname" (Join-Path $RawDir "01_hostname.txt")
Add-ReportSection "BASIC - systeminfo" (Join-Path $RawDir "02_systeminfo.txt")
Add-ReportSection "NETWORK - ipconfig /all" (Join-Path $RawDir "03_ipconfig_all.txt")
Add-ReportSection "NETWORK - route print" (Join-Path $RawDir "04_route_print.txt")
Add-ReportSection "SYSTEM - computer summary" (Join-Path $RawDir "05_computer_summary.csv")
Add-ReportSection "ROLES - installed Windows features" (Join-Path $RawDir "06_installed_windows_features.csv")
Add-ReportSection "SERVICES - running services" (Join-Path $RawDir "07_running_services.csv")
Add-ReportSection "SOFTWARE - installed software" (Join-Path $RawDir "08_installed_software.csv")
Add-ReportSection "NETWORK - TCP connections and listening ports" (Join-Path $RawDir "09_tcp_connections.csv")
Add-ReportSection "FILE SHARING - SMB shares" (Join-Path $RawDir "10_smb_shares.csv")
Add-ReportSection "SCHEDULED TASKS" (Join-Path $RawDir "11_scheduled_tasks.csv")
Add-ReportSection "STORAGE - volumes" (Join-Path $RawDir "12_volumes.csv")
Add-ReportSection "STORAGE - disks" (Join-Path $RawDir "13_disks.csv")
Add-ReportSection "PROCESS - top CPU" (Join-Path $RawDir "14_processes_top_cpu.csv")
Add-ReportSection "PROCESS - top memory" (Join-Path $RawDir "15_processes_top_memory.csv")
Add-ReportSection "VIRTUALIZATION - Hyper-V VMs" (Join-Path $RawDir "16_hyperv_vms.csv")
Add-ReportSection "LOGS - system errors last 7 days" (Join-Path $RawDir "17_system_errors_last_7_days.csv")
Add-ReportSection "LOGS - application errors last 7 days" (Join-Path $RawDir "18_application_errors_last_7_days.csv")

Write-Host ""
Write-Host "[*] Assessment completed."
Write-Host "[*] Recommendation: $rec"
Write-Host "[*] Single report: $ReportPath"
Write-Host "[*] Raw files are stored in: $RawDir"
