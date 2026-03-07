rule panguard_ssrf_github-a
{
    meta:
        description = "Detects SSRF payload patterns targeting internal networks"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27739"
        report_title = "Angular SSR is vulnerable to SSRF and Header Injection via request handling pipeline"
        confidence = 85
        cwe = "CWE-918"
        mitre = "T1190, T1071"

    strings:
        $localhost = "127.0.0.1" nocase
        $metadata_aws = "169.254.169.254" nocase
        $metadata_gcp = "metadata.google.internal" nocase
        $internal_10 = "10.0.0." nocase
        $internal_172 = "172.16." nocase
        $internal_192 = "192.168." nocase

    condition:
        2 of them
}