param(
    [string]$OutputRoot = ".\ServerAssessment"
)

$ErrorActionPreference = "Continue"
$ComputerName = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $OutputRoot "$ComputerName`_$Timestamp"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$Findings = New-Object System.Collections.Generic.List[Object]

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Details, [string]$Evidence)
    $Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Details  = $Details
        Evidence = $Evidence
    })
}

function Save-Text {
    param([string]$Name, [scriptblock]$Command)
    try {
        & $Command | Out-File -FilePath (Join-Path $OutputDir "$Name.txt") -Encoding UTF8
    } catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $OutputDir "$Name.txt") -Encoding UTF8
    }
}

function Save-Csv {
    param([string]$Name, [scriptblock]$Command)
    try {
        & $Command | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$Name.csv")
    } catch {
        [PSCustomObject]@{ Error = $_.Exception.Message } |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$Name.csv")
    }
}

Write-Host "[*] Read-only assessment started."
Write-Host "[*] Output: $OutputDir"

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Add-Finding "Medium" "Permission Scope" "Running as non-administrator. Some results may be incomplete." $identity.Name
    }
} catch {
    Add-Finding "Medium" "Permission Scope" "Unable to determine administrator status." $_.Exception.Message
}

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
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "05_computer_summary.csv")

    if ($cs.DomainRole -in 4,5) {
        Add-Finding "Critical" "Domain Controller" "This server appears to be a Domain Controller." "DomainRole=$($cs.DomainRole)"
    }
} catch {
    Add-Finding "Medium" "System Info" "Failed to collect computer details." $_.Exception.Message
}

try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $features = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"}
        $features | Select-Object Name, DisplayName, InstallState |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "06_installed_windows_features.csv")

        foreach ($f in $features) {
            if ($f.Name -in @("AD-Domain-Services","DNS","DHCP","Hyper-V","Failover-Clustering")) {
                Add-Finding "Critical" "Installed Role" "Critical Windows role installed: $($f.DisplayName)" $f.Name
            } elseif ($f.Name -in @("File-Services","Web-Server","Windows-Server-Backup","Remote-Desktop-Services")) {
                Add-Finding "High" "Installed Role" "Important Windows role installed: $($f.DisplayName)" $f.Name
            }
        }
    } else {
        Add-Finding "Low" "Windows Feature" "Get-WindowsFeature unavailable." "Possible non-server OS or missing module."
    }
} catch {
    Add-Finding "Medium" "Windows Feature" "Failed to collect Windows features." $_.Exception.Message
}

Save-Csv "07_running_services" {
    Get-CimInstance Win32_Service |
        Where-Object {$_.State -eq "Running"} |
        Select-Object Name, DisplayName, State, StartMode, PathName
}

try {
    $services = Get-CimInstance Win32_Service | Where-Object {$_.State -eq "Running"}
    $criticalPatterns = "NTDS|DNS|DHCPServer|MSSQL|SQLSERVERAGENT|MySQL|MariaDB|PostgreSQL|OracleService|Veeam|Acronis|vmms|MSExchange"
    $highPatterns = "W3SVC|IIS|Apache|Nginx|Tomcat|Splunk|Zabbix|PRTG|Backup|License|FlexNet|Sentinel"

    foreach ($s in $services) {
        if (($s.Name -match $criticalPatterns) -or ($s.DisplayName -match $criticalPatterns)) {
            Add-Finding "Critical" "Running Service" "Critical service indicator found: $($s.DisplayName)" $s.Name
        } elseif (($s.Name -match $highPatterns) -or ($s.DisplayName -match $highPatterns)) {
            Add-Finding "High" "Running Service" "Important service indicator found: $($s.DisplayName)" $s.Name
        }
    }
} catch {
    Add-Finding "Medium" "Running Service" "Failed to analyze services." $_.Exception.Message
}

try {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $programs = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object {$_.DisplayName} |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }

    $programs | Sort-Object DisplayName -Unique |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "08_installed_software.csv")

    foreach ($p in $programs) {
        if ($p.DisplayName -match "SQL Server|MySQL|MariaDB|PostgreSQL|Oracle|Veeam|Acronis|Backup|VMware|Hyper-V|Splunk|Zabbix|PRTG|License|FlexNet|Sentinel|ERP|WMS|CRM") {
            Add-Finding "High" "Installed Software" "Business/infrastructure software indicator found: $($p.DisplayName)" $p.DisplayName
        }
    }
} catch {
    Add-Finding "Medium" "Installed Software" "Failed to collect installed software." $_.Exception.Message
}

try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

        $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object {$_.State -in @("Listen","Established")} |
            ForEach-Object {
                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort = $_.RemotePort
                    State = $_.State
                    ProcessId = $_.OwningProcess
                    ProcessName = $procMap[$_.OwningProcess]
                }
            }

        $tcp | Sort-Object State, LocalPort |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "09_tcp_connections.csv")

        $criticalPorts = @(53,67,88,135,139,389,445,636,1433,1521,3306,5432)
        $highPorts = @(80,443,3389,5985,5986,8080,8443)

        foreach ($c in $tcp | Where-Object {$_.State -eq "Listen"}) {
            if ($criticalPorts -contains [int]$c.LocalPort) {
                Add-Finding "Critical" "Listening Port" "Critical port listening: $($c.LocalPort)" "Process: $($c.ProcessName)"
            } elseif ($highPorts -contains [int]$c.LocalPort) {
                Add-Finding "High" "Listening Port" "Important port listening: $($c.LocalPort)" "Process: $($c.ProcessName)"
            }
        }

        $active = $tcp | Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -notin @("127.0.0.1","::1","0.0.0.0","::")
        }

        if (($active | Measure-Object).Count -gt 0) {
            Add-Finding "High" "Active Connections" "Active remote connections detected." "Count: $(($active | Measure-Object).Count)"
        }
    } else {
        Save-Text "09_netstat_ano" { netstat -ano }
        Add-Finding "Low" "Network" "Get-NetTCPConnection unavailable; netstat collected instead." "09_netstat_ano.txt"
    }
} catch {
    Add-Finding "Medium" "Network" "Failed to collect TCP connection information." $_.Exception.Message
}

try {
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        $shares | Select-Object Name, Path, Description, ShareState, ShareType |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "10_smb_shares.csv")

        $userShares = $shares | Where-Object {
            $_.Name -notmatch "^[A-Z]\$$" -and $_.Name -notin @("ADMIN$","IPC$","print$")
        }

        if (($userShares | Measure-Object).Count -gt 0) {
            Add-Finding "High" "File Sharing" "Non-default SMB shares found." "Shares: $($userShares.Name -join ', ')"
        }
    }
} catch {
    Add-Finding "Medium" "SMB" "Failed to collect SMB share information." $_.Exception.Message
}

try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Disabled"}
    $taskReport = foreach ($t in $tasks) {
        [PSCustomObject]@{
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State = $t.State
            Actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " ; "
        }
    }

    $taskReport | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "11_scheduled_tasks.csv")

    $interesting = $taskReport | Where-Object {
        $_.TaskName -match "backup|sync|sql|mysql|dump|report|ftp|sftp|robocopy|copy|veeam|acronis" -or
        $_.Actions -match "backup|sync|sql|mysql|dump|report|ftp|sftp|robocopy|copy|veeam|acronis"
    }

    if (($interesting | Measure-Object).Count -gt 0) {
        Add-Finding "High" "Scheduled Tasks" "Backup/sync/report/database scheduled task indicator found." "Count: $(($interesting | Measure-Object).Count)"
    }
} catch {
    Add-Finding "Medium" "Scheduled Tasks" "Failed to collect scheduled tasks." $_.Exception.Message
}

Save-Csv "12_volumes" {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, SizeRemaining, Size
}
Save-Csv "13_disks" {
    Get-Disk | Select-Object Number, FriendlyName, SerialNumber, HealthStatus, OperationalStatus, Size, PartitionStyle
}
Save-Csv "14_processes_top_cpu" {
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name, Id, CPU, WorkingSet, Path
}
Save-Csv "15_processes_top_memory" {
    Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 30 Name, Id, CPU, WorkingSet, Path
}

try {
    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
        $vms = Get-VM -ErrorAction SilentlyContinue
        $vms | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime, Status |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "16_hyperv_vms.csv")

        if (($vms | Measure-Object).Count -gt 0) {
            Add-Finding "Critical" "Virtualization" "Hyper-V virtual machines detected." "VM count: $(($vms | Measure-Object).Count)"
        }
    }
} catch {
    Add-Finding "Medium" "Hyper-V" "Failed to collect Hyper-V information." $_.Exception.Message
}

try {
    Get-WinEvent -FilterHashtable @{LogName="System"; Level=2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "17_system_errors_last_7_days.csv")

    Get-WinEvent -FilterHashtable @{LogName="Application"; Level=2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "18_application_errors_last_7_days.csv")
} catch {
    Add-Finding "Low" "Event Logs" "Failed to collect event log errors." $_.Exception.Message
}

$Findings | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "00_findings.csv")

$critical = ($Findings | Where-Object {$_.Severity -eq "Critical"} | Measure-Object).Count
$high = ($Findings | Where-Object {$_.Severity -eq "High"} | Measure-Object).Count
$medium = ($Findings | Where-Object {$_.Severity -eq "Medium"} | Measure-Object).Count

if ($critical -gt 0) {
    $rec = "DO NOT REMOVE DIRECTLY"
    $reason = "Critical indicators were found: AD/DNS/DHCP/database/backup/virtualization or similar."
} elseif ($high -ge 3) {
    $rec = "MIGRATION REQUIRED BEFORE REMOVAL"
    $reason = "Multiple important services or dependencies were found."
} elseif ($high -gt 0 -or $medium -gt 0) {
    $rec = "POTENTIAL DECOMMISSION CANDIDATE AFTER MANUAL CONFIRMATION"
    $reason = "Some indicators were found, or the script ran with limited permission."
} else {
    $rec = "LOW-RISK CANDIDATE BUT STILL NEEDS BUSINESS CONFIRMATION"
    $reason = "No major indicators were detected within the current permission scope."
}

@"
Server Decommission Assessment Summary
=====================================

Server: $ComputerName
Timestamp: $Timestamp
Output Directory: $OutputDir

Preliminary Recommendation:
$rec

Reason:
$reason

Finding Counts:
Critical: $critical
High:     $high
Medium:   $medium

Important:
- This is a read-only local assessment.
- If this script ran as a normal user, the result is incomplete by design.
- Final decommission decision requires customer IT confirmation, backup validation, dependency review, and maintenance-window testing.
"@ | Out-File -FilePath (Join-Path $OutputDir "00_assessment_summary.txt") -Encoding UTF8

Write-Host ""
Write-Host "[*] Assessment completed."
Write-Host "[*] Recommendation: $rec"
Write-Host "[*] Report folder: $OutputDir"
