rule panguard_deserialization_cisa-kev
{
    meta:
        description = "Detects insecure deserialization payloads (Java, PHP, Python)"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38203"
        report_title = "Adobe ColdFusion Deserialization of Untrusted Data Vulnerability"
        confidence = 85
        mitre = "T1059"

    strings:
        $java_serial = { ac ed 00 05 }
        $java_base64 = "rO0AB" nocase
        $php_serial = /O:\d+:"/ nocase
        $python_pickle = "__reduce__" nocase
        $pickle_loads = "pickle.loads" nocase

    condition:
        2 of them
}