rule panguard_information_disclosure_cisa-kev
{
    meta:
        description = "Detects information disclosure patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-49103"
        report_title = "ownCloud graphapi Information Disclosure Vulnerability"
        confidence = 75
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