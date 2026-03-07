rule panguard_sqli_cisa-kev
{
    meta:
        description = "Detects SQL injection attack patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-48788"
        report_title = "Fortinet FortiClient EMS SQL Injection Vulnerability"
        confidence = 85
        mitre = "T1190"

    strings:
        $union_select = "UNION SELECT" nocase
        $or_true = "' OR '1'='1" nocase
        $comment_dash = "1=1--" nocase
        $sleep_func = "SLEEP(" nocase
        $benchmark_func = "BENCHMARK(" nocase
        $waitfor_delay = "WAITFOR DELAY" nocase

    condition:
        2 of them
}