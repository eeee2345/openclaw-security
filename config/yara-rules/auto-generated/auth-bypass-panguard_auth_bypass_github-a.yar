rule panguard_auth_bypass_github-a
{
    meta:
        description = "Detects authentication bypass header manipulation"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://panguard.ai/intel/github-advisory:GHSA-jh8h-6c9q-7gmw"
        report_title = "n8n has an Authentication Bypass in its Chat Trigger Node"
        confidence = 60
        cwe = "CWE-287"
        mitre = "T1078"

    strings:
        $forwarded_for = "X-Forwarded-For:" nocase
        $original_url = "X-Original-URL:" nocase
        $rewrite_url = "X-Rewrite-URL:" nocase
        $admin_path = "/admin/" nocase
        $internal_path = "/internal/" nocase

    condition:
        3 of them
}