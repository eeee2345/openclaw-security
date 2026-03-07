rule panguard_xss_3424998
{
    meta:
        description = "Detects cross-site scripting payloads"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3424998"
        report_title = "AI Playground XSS to steal user-chat messages and access to connected MCP Server"
        confidence = 45
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