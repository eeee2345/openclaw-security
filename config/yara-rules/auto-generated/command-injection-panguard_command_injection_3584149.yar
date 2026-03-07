rule panguard_command_injection_3584149
{
    meta:
        description = "Detects OS command injection patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3584149"
        report_title = "SSTI leads to Command injection"
        confidence = 30
        mitre = "T1059"

    strings:
        $cmd_pipe = "/bin/sh -c" nocase
        $cmd_bash = "/bin/bash -c" nocase
        $cmd_powershell = "powershell.exe" nocase
        $cmd_exec = "cmd.exe /c" nocase
        $backtick_exec = /`[^`]{2,40}`/ nocase

    condition:
        3 of them
}