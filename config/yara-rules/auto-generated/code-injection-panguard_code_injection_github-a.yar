rule panguard_code_injection_github-a
{
    meta:
        description = "Detects code injection payloads in files or network captures"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27493"
        report_title = "n8n has Unauthenticated Expression Evaluation via Form Node"
        confidence = 85
        cwe = "CWE-94"
        mitre = "T1059"

    strings:
        $eval_call = "eval(" nocase
        $exec_call = "exec(" nocase
        $system_call = "system(" nocase
        $spawn_call = "spawn(" nocase
        $runtime_exec = "Runtime.getRuntime()" nocase
        $python_import = "__import__" nocase

    condition:
        2 of them
}