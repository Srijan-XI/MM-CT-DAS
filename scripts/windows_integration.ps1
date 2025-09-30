# MM-CT-DAS Windows Integration Script
# PowerShell script for Windows-specific cybersecurity operations

param(
    [string]$Action,
    [string]$Parameter
)

function Block-IPAddress {
    param([string]$IP)
    
    try {
        $RuleName = "MM-CT-DAS-Block-$($IP -replace '\.', '-')"
        
        # Check if rule already exists
        $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if ($ExistingRule) {
            Write-Output "IP $IP is already blocked"
            return $true
        }
        
        # Create new firewall rule
        New-NetFirewallRule -DisplayName $RuleName `
                           -Direction Inbound `
                           -Protocol Any `
                           -Action Block `
                           -RemoteAddress $IP `
                           -Description "Blocked by MM-CT-DAS - Threat detected"
        
        Write-Output "Successfully blocked IP: $IP"
        return $true
    }
    catch {
        Write-Error "Failed to block IP $IP : $($_.Exception.Message)"
        return $false
    }
}

function Unblock-IPAddress {
    param([string]$IP)
    
    try {
        $RuleName = "MM-CT-DAS-Block-$($IP -replace '\.', '-')"
        
        # Remove firewall rule
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        Write-Output "Successfully unblocked IP: $IP"
        return $true
    }
    catch {
        Write-Error "Failed to unblock IP $IP : $($_.Exception.Message)"
        return $false
    }
}

function Get-NetworkInterfaces {
    try {
        $Interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        
        foreach ($Interface in $Interfaces) {
            Write-Output "Interface: $($Interface.Name) ($($Interface.InterfaceDescription))"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to get network interfaces: $($_.Exception.Message)"
        return $false
    }
}

function Get-SuspiciousProcesses {
    try {
        # Get processes with suspicious characteristics
        $Processes = Get-Process | Where-Object {
            $_.ProcessName -match "(cmd|powershell|wscript|cscript)" -or
            $_.CPU -gt 50 -or
            $_.WorkingSet -gt 100MB
        }
        
        foreach ($Process in $Processes) {
            Write-Output "Process: $($Process.ProcessName) (PID: $($Process.Id), CPU: $($Process.CPU), Memory: $($Process.WorkingSet))"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to get suspicious processes: $($_.Exception.Message)"
        return $false
    }
}

function Kill-SuspiciousProcess {
    param([int]$ProcessId)
    
    try {
        $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        
        if ($Process) {
            Stop-Process -Id $ProcessId -Force
            Write-Output "Successfully terminated process ID: $ProcessId"
            return $true
        }
        else {
            Write-Output "Process ID $ProcessId not found"
            return $false
        }
    }
    catch {
        Write-Error "Failed to kill process $ProcessId : $($_.Exception.Message)"
        return $false
    }
}

function Get-EventLogThreats {
    param([int]$Hours = 24)
    
    try {
        $StartTime = (Get-Date).AddHours(-$Hours)
        
        # Check Windows Security log for suspicious events
        $SecurityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $StartTime
            ID = 4625, 4648, 4719, 4724, 4725  # Failed logons, suspicious activities
        } -ErrorAction SilentlyContinue
        
        # Check System log for suspicious events
        $SystemEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $StartTime
            Level = 1, 2, 3  # Critical, Error, Warning
        } -ErrorAction SilentlyContinue
        
        Write-Output "Found $($SecurityEvents.Count) security events and $($SystemEvents.Count) system events in last $Hours hours"
        
        return $true
    }
    catch {
        Write-Error "Failed to get event log threats: $($_.Exception.Message)"
        return $false
    }
}

function Test-NetworkConnectivity {
    param([string]$Target = "8.8.8.8")
    
    try {
        $Result = Test-NetConnection -ComputerName $Target -Port 53 -InformationLevel Quiet
        
        if ($Result) {
            Write-Output "Network connectivity OK (tested against $Target)"
        }
        else {
            Write-Output "Network connectivity FAILED (tested against $Target)"
        }
        
        return $Result
    }
    catch {
        Write-Error "Failed to test network connectivity: $($_.Exception.Message)"
        return $false
    }
}

function Get-FirewallStatus {
    try {
        $FirewallProfiles = Get-NetFirewallProfile
        
        foreach ($Profile in $FirewallProfiles) {
            Write-Output "Firewall Profile: $($Profile.Name) - Enabled: $($Profile.Enabled)"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to get firewall status: $($_.Exception.Message)"
        return $false
    }
}

# Main script logic
switch ($Action.ToLower()) {
    "block-ip" {
        Block-IPAddress -IP $Parameter
    }
    "unblock-ip" {
        Unblock-IPAddress -IP $Parameter
    }
    "get-interfaces" {
        Get-NetworkInterfaces
    }
    "get-processes" {
        Get-SuspiciousProcesses
    }
    "kill-process" {
        Kill-SuspiciousProcess -ProcessId $Parameter
    }
    "get-events" {
        Get-EventLogThreats -Hours 24
    }
    "test-network" {
        Test-NetworkConnectivity
    }
    "firewall-status" {
        Get-FirewallStatus
    }
    default {
        Write-Output "MM-CT-DAS Windows Integration Script"
        Write-Output "Usage: .\windows_integration.ps1 -Action <action> [-Parameter <parameter>]"
        Write-Output ""
        Write-Output "Available Actions:"
        Write-Output "  block-ip <IP>        - Block IP address in Windows Firewall"
        Write-Output "  unblock-ip <IP>      - Unblock IP address in Windows Firewall"
        Write-Output "  get-interfaces       - List network interfaces"
        Write-Output "  get-processes        - List suspicious processes"
        Write-Output "  kill-process <PID>   - Kill process by ID"
        Write-Output "  get-events           - Get suspicious Windows events"
        Write-Output "  test-network         - Test network connectivity"
        Write-Output "  firewall-status      - Check Windows Firewall status"
    }
}