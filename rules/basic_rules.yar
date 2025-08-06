rule SuspiciousFile {
    meta:
        description = "Detects suspicious file characteristics"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 70
    strings:
         = "CreateRemoteThread" nocase
         = "VirtualAlloc" nocase
         = "WriteProcessMemory" nocase
         = "ShellExecute" nocase
         = "cmd.exe /c " nocase
         = "powershell.exe -e" nocase
         = "eval(base64_decode" nocase
         = "WScript.Shell" nocase
    condition:
        2 of them
}

rule MalwarePattern {
    meta:
        description = "Common malware patterns"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 85
    strings:
         = "botnet" nocase
         = "backdoor" nocase
         = "trojan" nocase
         = "keylogger" nocase
         = "ransomware" nocase
    condition:
        any of them
}

rule SuspiciousPacker {
    meta:
        description = "Detects common packer signatures"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 60
    strings:
         = "UPX!" wide ascii
         = "MPRESS" wide ascii
         = "ASPack" wide ascii
         = "FSG!" wide ascii
         = "PECompact" wide ascii
    condition:
        any of them
}
