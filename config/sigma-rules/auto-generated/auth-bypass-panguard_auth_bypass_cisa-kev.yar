rule panguard_auth_bypass_cisa-kev
{
    meta:
        description = "Detects authentication bypass header manipulation"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-46805"
        report_title = "Ivanti Connect Secure and Policy Secure Authentication Bypass Vulnerability"
        confidence = 85
        mitre = "T1078"

    strings:
        $forwarded_for = "X-Forwarded-For:" nocase
        $original_url = "X-Original-URL:" nocase
        $rewrite_url = "X-Rewrite-URL:" nocase
        $admin_path = "/admin/" nocase
        $internal_path = "/internal/" nocase

    condition:
        2 of them
}