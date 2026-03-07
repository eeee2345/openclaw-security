rule panguard_ssrf_cisa-kev
{
    meta:
        description = "Detects SSRF payload patterns targeting internal networks"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21893"
        report_title = "Ivanti Connect Secure, Policy Secure, and Neurons Server-Side Request Forgery (SSRF) Vulnerability"
        confidence = 85
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