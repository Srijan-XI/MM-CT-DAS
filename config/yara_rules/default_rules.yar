
rule SuspiciousNetworkActivity
{
    meta:
        description = "Detects suspicious network patterns"
        author = "MM-CT-DAS"
        date = "2025-09-29"
    
    strings:
        $http_malware = /GET \/[a-zA-Z0-9]{20,}\.exe/ nocase
        $suspicious_ua = "User-Agent: " nocase
        $shell_commands = /cmd\.exe|powershell\.exe|bash/ nocase
        
    condition:
        any of them
}

rule PortScanDetection
{
    meta:
        description = "Detects potential port scanning"
        author = "MM-CT-DAS"
        
    strings:
        $nmap_scan = "Nmap scan" nocase
        $syn_flood = /SYN.*flood/ nocase
        
    condition:
        any of them
}

rule DataExfiltration
{
    meta:
        description = "Detects potential data exfiltration"
        author = "MM-CT-DAS"
        
    strings:
        $base64_large = /[A-Za-z0-9+\/]{100,}/
        $ftp_upload = /STOR.*\.(zip|rar|7z|tar)/ nocase
        
    condition:
        any of them
}
