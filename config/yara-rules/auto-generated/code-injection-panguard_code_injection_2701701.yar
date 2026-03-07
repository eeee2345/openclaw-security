rule panguard_code_injection_2701701
{
    meta:
        description = "Detects code injection payloads in files or network captures"
        author = "Panguard Threat Intel (auto-generated)"
        date = "2026-03-07"
        reference = "https://hackerone.com/reports/2701701"
        report_title = "Injection in path parameter of Ingress-nginx"
        confidence = 75
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