rule panguard_information_disclosure_github-a
{
    meta:
        description = "Detects information disclosure patterns"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27457"
        report_title = "Weblate: Missing access control for the AddonViewSet API exposes all addon configurations"
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