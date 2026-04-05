/*
    YARA Rules — AI Hybrid Antivirus System
    
    These rules detect common malware characteristics in PE files.
    They serve as the rule-based detection layer alongside ML and ClamAV.
*/

rule Suspicious_UPX_Packed
{
    meta:
        description = "Detects UPX-packed executables (common packer for malware)"
        severity = "medium"
        category = "packer"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D and ($upx0 or $upx1 or $upx2)
}

rule Suspicious_Section_Names
{
    meta:
        description = "Detects PE files with suspicious or non-standard section names"
        severity = "medium"
        category = "obfuscation"

    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
        $s3 = ".ASPack" ascii
        $s4 = ".ccg" ascii
        $s5 = ".nsp0" ascii
        $s6 = ".nsp1" ascii
        $s7 = ".perplex" ascii
        $s8 = ".packed" ascii
        $s9 = ".RLPack" ascii
        $s10 = ".petite" ascii
        $s11 = ".yP" ascii
        $s12 = ".boom" ascii

    condition:
        uint16(0) == 0x5A4D and any of ($s*)
}

rule Suspicious_Imports_Keylogging
{
    meta:
        description = "Detects potential keylogging via suspicious API imports"
        severity = "high"
        category = "spyware"

    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetKeyState" ascii wide
        $api4 = "RegisterHotKey" ascii wide

    condition:
        uint16(0) == 0x5A4D and 2 of ($api*)
}

rule Suspicious_Imports_Injection
{
    meta:
        description = "Detects potential process injection techniques"
        severity = "high"
        category = "injection"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "OpenProcess" ascii wide

    condition:
        uint16(0) == 0x5A4D and 3 of ($api*)
}

rule Suspicious_Imports_Persistence
{
    meta:
        description = "Detects registry manipulation for persistence"
        severity = "high"
        category = "persistence"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide

    condition:
        uint16(0) == 0x5A4D and (1 of ($reg*)) and (1 of ($api*))
}

rule Suspicious_Imports_Download
{
    meta:
        description = "Detects potential dropper behavior (downloading files)"
        severity = "high"
        category = "dropper"

    strings:
        $api1 = "URLDownloadToFile" ascii wide
        $api2 = "InternetOpen" ascii wide
        $api3 = "HttpOpenRequest" ascii wide
        $api4 = "WinExec" ascii wide
        $api5 = "ShellExecute" ascii wide

    condition:
        uint16(0) == 0x5A4D and ($api1 or ($api2 and $api3)) and ($api4 or $api5)
}

rule Suspicious_AntiDebug
{
    meta:
        description = "Detects anti-debugging techniques"
        severity = "medium"
        category = "evasion"

    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "CheckRemoteDebuggerPresent" ascii wide
        $api3 = "NtQueryInformationProcess" ascii wide
        $api4 = "OutputDebugString" ascii wide

    condition:
        uint16(0) == 0x5A4D and 2 of ($api*)
}

rule Suspicious_CryptoRansom
{
    meta:
        description = "Detects potential ransomware behavior (crypto + file ops)"
        severity = "critical"
        category = "ransomware"

    strings:
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptAcquireContext" ascii wide
        $file1 = "FindFirstFile" ascii wide
        $file2 = "MoveFileEx" ascii wide
        $file3 = "DeleteFile" ascii wide
        $ext1 = ".encrypted" ascii wide nocase
        $ext2 = ".locked" ascii wide nocase
        $ext3 = ".crypto" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 2 of ($crypto*) and 1 of ($file*) and 1 of ($ext*)
}

rule Tiny_PE_Suspicious
{
    meta:
        description = "PE file smaller than 10KB is unusual for legitimate software"
        severity = "low"
        category = "anomaly"

    condition:
        uint16(0) == 0x5A4D and filesize < 10KB
}
