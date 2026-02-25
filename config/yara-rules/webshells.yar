rule WebShell_PHP_Generic {
    meta:
        id = "yara-001"
        description = "Detects common PHP web shell patterns"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "critical"
        mitre_attack = "T1505.003"
    strings:
        $eval = "eval(" ascii nocase
        $exec = "exec(" ascii nocase
        $system = "system(" ascii nocase
        $passthru = "passthru(" ascii nocase
        $shell_exec = "shell_exec(" ascii nocase
        $base64 = "base64_decode(" ascii nocase
        $assert = "assert(" ascii nocase
        $preg_replace_e = /preg_replace\s*\(\s*['"]\/.+\/e['"]/
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
        $wso = "WSO " ascii
        $b374k = "b374k" ascii
    condition:
        (uint32(0) == 0x68703F3C or uint16(0) == 0x3F3C) and
        (3 of ($eval, $exec, $system, $passthru, $shell_exec, $base64, $assert, $preg_replace_e) or
         any of ($c99, $r57, $wso, $b374k))
}

rule WebShell_JSP_Generic {
    meta:
        id = "yara-002"
        description = "Detects common JSP web shell patterns"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "critical"
        mitre_attack = "T1505.003"
    strings:
        $runtime_exec = "Runtime.getRuntime().exec" ascii
        $process_builder = "ProcessBuilder" ascii
        $cmd_param = "request.getParameter(\"cmd\")" ascii
        $shell_param = "request.getParameter(\"shell\")" ascii
    condition:
        any of them
}

rule WebShell_ASPX_Generic {
    meta:
        id = "yara-003"
        description = "Detects common ASPX web shell patterns"
        author = "OpenClaw Security"
        date = "2026-02-25"
        severity = "critical"
        mitre_attack = "T1505.003"
    strings:
        $process_start = "Process.Start" ascii
        $cmd_exe = "cmd.exe" ascii
        $powershell = "powershell" ascii nocase
        $request_cmd = "Request[\"cmd\"]" ascii
        $request_exec = "Request.QueryString[\"exec\"]" ascii
    condition:
        2 of them
}
