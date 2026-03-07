rule panguard_xss_3447021
{
    meta:
        description = "Detects cross-site scripting payloads"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3447021"
        report_title = "XSS Vulnerability on Pressable/Atomic Hosting Platform via unescaped admin notices leads to code execution"
        confidence = 60
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