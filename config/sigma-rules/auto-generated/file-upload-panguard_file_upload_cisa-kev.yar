rule panguard_file_upload_cisa-kev
{
    meta:
        description = "Detects malicious file upload payloads and webshells"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50623"
        report_title = "Cleo Multiple Products Unrestricted File Upload Vulnerability"
        confidence = 85
        mitre = "T1105"

    strings:
        $php_tag = "<?php" nocase
        $php_short = "<?=" nocase
        $jsp_tag = "<%@" nocase
        $asp_tag = "<%eval" nocase
        $webshell_passthru = "passthru(" nocase
        $webshell_shell_exec = "shell_exec(" nocase

    condition:
        2 of them
}