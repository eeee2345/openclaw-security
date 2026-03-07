rule panguard_sqli_3293803
{
    meta:
        description = "Detects SQL injection attack patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3293803"
        report_title = "SQLi At `███████` via `theme_name` "
        confidence = 85
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