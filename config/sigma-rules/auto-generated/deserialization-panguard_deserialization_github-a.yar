rule panguard_deserialization_github-a
{
    meta:
        description = "Detects insecure deserialization payloads (Java, PHP, Python)"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27794"
        report_title = "LangGraph: BaseCache Deserialization of Untrusted Data may lead to Remote Code Execution"
        confidence = 60
        cwe = "CWE-502"
        mitre = "T1059"

    strings:
        $java_serial = { ac ed 00 05 }
        $java_base64 = "rO0AB" nocase
        $php_serial = /O:\d+:"/ nocase
        $python_pickle = "__reduce__" nocase
        $pickle_loads = "pickle.loads" nocase

    condition:
        3 of them
}