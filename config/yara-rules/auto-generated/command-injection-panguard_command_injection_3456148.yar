rule panguard_command_injection_3456148
{
    meta:
        description = "Detects OS command injection patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3456148"
        report_title = "Unbounded decompression chain in HTTP responses on Node.js Fetch API via Content-Encoding leads to resource exhaustion"
        confidence = 60
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