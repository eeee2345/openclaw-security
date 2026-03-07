rule panguard_command_injection_github-a
{
    meta:
        description = "Detects OS command injection patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27965"
        report_title = "Vitess users with backup storage access can gain unauthorized access to production deployment environments"
        confidence = 75
        cwe = "CWE-78"
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