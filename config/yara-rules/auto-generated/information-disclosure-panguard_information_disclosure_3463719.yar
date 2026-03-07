rule panguard_information_disclosure_3463719
{
    meta:
        description = "Detects information disclosure patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3463719"
        report_title = "ASLR leak in Mario Kart World through LAN mode"
        confidence = 75
        cwe = "CWE-200"
        mitre = "T1082"

    strings:
        $env_file = ".env" nocase
        $git_dir = ".git/config" nocase
        $phpinfo = "phpinfo()" nocase
        $actuator = "/actuator/" nocase
        $debug_endpoint = "/debug/" nocase

    condition:
        2 of them
}