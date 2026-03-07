rule panguard_sqli_github-a
{
    meta:
        description = "Detects SQL injection attack patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3105"
        report_title = "Mautic is Vulnerable to SQL Injection through Contact Activity API Sorting"
        confidence = 75
        cwe = "CWE-89"
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