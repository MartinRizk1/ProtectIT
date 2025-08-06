rule suspicious_strings {
    strings:
        $cmd_exec = "WScript.Shell" nocase
        $registry = "RegWrite" nocase
        $download = "DownloadFile" nocase
        $create_object = "CreateObject" nocase
        $powershell = "powershell" nocase
        $exec = "cmd.exe" nocase
        $eval = "eval(" nocase
        $encoded_content = "base64" nocase
        
    condition:
        any of them
}

rule suspicious_executables {
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $suspicious_section = ".evil" nocase
        
    condition:
        ($mz at 0) and $pe and any of ($suspicious*)
}

rule potential_ransomware {
    strings:
        $encrypt_string1 = "encrypt" nocase
        $encrypt_string2 = "ransom" nocase
        $encrypt_string3 = "bitcoin" nocase
        $encrypt_string4 = "payment" nocase
        $encrypt_string5 = "decrypt" nocase
        
    condition:
        2 of ($encrypt_string*)
}

rule suspicious_scripts {
    strings:
        $obfuscation1 = "String.fromCharCode" nocase
        $obfuscation2 = "eval(atob" nocase
        $obfuscation3 = "document.write(unescape" nocase
        $obfuscation4 = "FromBase64String" nocase
        $obfuscation5 = "hidden iframe" nocase
        
    condition:
        any of them
}

rule suspicious_macro {
    strings:
        $auto_exec1 = "Auto_Open" nocase
        $auto_exec2 = "AutoOpen" nocase
        $auto_exec3 = "Document_Open" nocase
        $auto_exec4 = "AutoExec" nocase
        $auto_exec5 = "AutoClose" nocase
        $susp_function1 = "Shell" nocase
        $susp_function2 = "VBA.CreateObject" nocase
        $susp_function3 = "ActiveX" nocase
        
    condition:
        any of ($auto_exec*) and any of ($susp_function*)
}

rule malicious_pe_characteristics {
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $antivm1 = "VirtualBox" nocase
        $antivm2 = "VMware" nocase
        $antivm3 = "QEMU" nocase
        $antivm4 = "Sandbox" nocase
        $antidbg1 = "IsDebuggerPresent" nocase
        $antidbg2 = "CheckRemoteDebuggerPresent" nocase
        $antidbg3 = "NtQueryInformationProcess" nocase
        
    condition:
        ($mz at 0) and $pe and (any of ($antivm*) or any of ($antidbg*))
}

rule suspicious_network_activity {
    strings:
        $network1 = "InternetOpenUrl" nocase
        $network2 = "URLDownloadToFile" nocase
        $network3 = "WSAStartup" nocase
        $network4 = "connect(" nocase
        $network5 = "recv(" nocase
        $network6 = "send(" nocase
        $network7 = "socket(" nocase
        $c2server1 = /https?:\/\/[a-z0-9]{10,}\.com\//
        $c2server2 = /https?:\/\/[a-z0-9]{6,}\.(xyz|top|club|info|cc|io|ru)\//
        
    condition:
        3 of them
}

rule suspicious_injection_techniques {
    strings:
        $inject1 = "VirtualAllocEx" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $inject4 = "SetWindowsHookEx" nocase
        $inject5 = "NtMapViewOfSection" nocase
        
    condition:
        2 of them
}

rule advanced_persistence_techniques {
    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved" nocase
        $reg4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" nocase
        $reg5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" nocase
        $sched1 = "schtasks" nocase
        $sched2 = "/create" nocase
        
    condition:
        any of ($reg*) or (all of ($sched*))
}
