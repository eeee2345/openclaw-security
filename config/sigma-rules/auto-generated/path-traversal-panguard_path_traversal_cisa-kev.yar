rule panguard_path_traversal_cisa-kev
{
    meta:
        description = "Detects directory traversal attack patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41266"
        report_title = "Qlik Sense Path Traversal Vulnerability"
        confidence = 85
        mitre = "T1083"

    strings:
        $dot_dot_slash = "../" nocase
        $encoded_traversal = "%2e%2e%2f" nocase
        $double_encoded = "..%252f" nocase
        $etc_passwd = "/etc/passwd" nocase
        $etc_shadow = "/etc/shadow" nocase
        $null_byte = "%00" nocase

    condition:
        2 of them
}