rule panguard_xss_github-a
{
    meta:
        description = "Detects cross-site scripting payloads"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25734"
        report_title = "Rucio WebUI has Stored Cross-site Scripting (XSS) in RSE Metadata"
        confidence = 60
        cwe = "CWE-79"
        mitre = "T1059.007"

    strings:
        $script_tag = "<script" nocase
        $javascript_proto = "javascript:" nocase
        $onerror_handler = "onerror=" nocase
        $onload_handler = "onload=" nocase
        $document_cookie = "document.cookie" nocase
        $svg_tag = "<svg/onload=" nocase

    condition:
        3 of them
}