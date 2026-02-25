rule Suspicious_Bash_Script {
    meta:
        id = "yara-008"
        description = "Detects suspicious bash scripts with evasion or attack patterns"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "high"
        mitre_attack = "T1059.004"
    strings:
        $shebang = "#!/bin/bash" ascii
        $shebang2 = "#!/bin/sh" ascii
        $curl_pipe = /curl\s+.*\|\s*(ba)?sh/ ascii
        $wget_pipe = /wget\s+.*-O\s*-\s*\|\s*(ba)?sh/ ascii
        $base64_decode = /echo\s+.*\|\s*base64\s+-d/ ascii
        $disable_history = "unset HISTFILE" ascii
        $disable_history2 = "HISTSIZE=0" ascii
        $rm_logs = /rm\s+(-rf?\s+)?\/(var\/log|tmp)/ ascii
        $iptables_flush = "iptables -F" ascii
        $chmod_suid = /chmod\s+[u+]?[0-7]*s/ ascii
        $nc_reverse = /nc\s+.*-e\s+\/bin/ ascii
    condition:
        ($shebang at 0 or $shebang2 at 0) and
        3 of ($curl_pipe, $wget_pipe, $base64_decode, $disable_history,
               $disable_history2, $rm_logs, $iptables_flush, $chmod_suid, $nc_reverse)
}

rule Suspicious_Python_Script {
    meta:
        id = "yara-009"
        description = "Detects suspicious Python scripts with attack/exfil patterns"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "high"
        mitre_attack = "T1059.006"
    strings:
        $import_socket = "import socket" ascii
        $import_subprocess = "import subprocess" ascii
        $import_os = "import os" ascii
        $reverse_shell = "socket.socket(socket.AF_INET" ascii
        $exec_cmd = "subprocess.call" ascii
        $exec_cmd2 = "subprocess.Popen" ascii
        $exec_cmd3 = "os.system(" ascii
        $base64_import = "import base64" ascii
        $keylog = "pynput" ascii
    condition:
        ($import_socket and $reverse_shell) or
        ($import_subprocess and $base64_import) or
        (2 of ($exec_cmd, $exec_cmd2, $exec_cmd3) and $import_os)
}

rule Obfuscated_JavaScript {
    meta:
        id = "yara-010"
        description = "Detects obfuscated JavaScript commonly used in attacks"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "medium"
        mitre_attack = "T1027"
    strings:
        $eval = "eval(" ascii
        $unescape = "unescape(" ascii
        $fromCharCode = "String.fromCharCode(" ascii
        $long_hex = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/ ascii
        $long_unicode = /\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){10,}/ ascii
        $atob = "atob(" ascii
        $document_write = "document.write(" ascii
    condition:
        ($eval and $unescape) or
        ($eval and $fromCharCode) or
        ($eval and ($long_hex or $long_unicode)) or
        ($atob and $document_write and ($long_hex or $long_unicode))
}
