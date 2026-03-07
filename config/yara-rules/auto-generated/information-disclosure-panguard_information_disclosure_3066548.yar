rule panguard_information_disclosure_3066548
{
    meta:
        description = "Detects information disclosure patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/3066548"
        report_title = "███████ - Publicly Accessible public_html Directory Exposing WordPress Configuration"
        confidence = 60
        cwe = "CWE-200"
        mitre = "T1082"

    strings:
        $env_file = ".env" nocase
        $git_dir = ".git/config" nocase
        $phpinfo = "phpinfo()" nocase
        $actuator = "/actuator/" nocase
        $debug_endpoint = "/debug/" nocase

    condition:
        3 of them
}