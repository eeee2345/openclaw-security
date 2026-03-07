rule panguard_xxe_cisa-kev
{
    meta:
        description = "Detects XML External Entity injection payloads"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-45727"
        report_title = "North Grid Proself Improper Restriction of XML External Entity (XXE) Reference Vulnerability"
        confidence = 75
        mitre = "T1190"

    strings:
        $entity_decl = "<!ENTITY" nocase
        $doctype_decl = "<!DOCTYPE" nocase
        $system_file = "SYSTEM \"file:" nocase
        $system_http = "SYSTEM \"http:" nocase
        $parameter_entity = /<!ENTITY\s+%\s+\w+/ nocase

    condition:
        2 of them
}