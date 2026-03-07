rule panguard_command_injection_cisa-kev
{
    meta:
        description = "Detects OS command injection patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1671"
        report_title = "Sophos Web Appliance Command Injection Vulnerability"
        confidence = 75
        mitre = "T1059"

    strings:
        $cmd_pipe = "/bin/sh -c" nocase
        $cmd_bash = "/bin/bash -c" nocase
        $cmd_powershell = "powershell.exe" nocase
        $cmd_exec = "cmd.exe /c" nocase
        $backtick_exec = /`[^`]{2,40}`/ nocase

    condition:
        2 of them
}