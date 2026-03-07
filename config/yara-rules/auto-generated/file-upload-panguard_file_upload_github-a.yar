rule panguard_file_upload_github-a
{
    meta:
        description = "Detects malicious file upload payloads and webshells"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-28502"
        report_title = "AVideo has Authenticated Remote Code Execution via Unsafe Plugin ZIP Extraction"
        confidence = 85
        cwe = "CWE-434"
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