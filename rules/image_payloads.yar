rule image_appended_zip_payload
{
    meta:
        finding_type = "YARA_APPENDED_ZIP"
        severity = "HIGH"
        score = 25
        confidence = "high"
        evidence_source = "validated binary structure"
        message = "YARA matched an appended ZIP payload after the image EOF"
    strings:
        $zip_local = { 50 4B 03 04 }
    condition:
        $zip_local at 0
}

rule image_appended_valid_pe
{
    meta:
        finding_type = "YARA_EMBEDDED_PE"
        severity = "CRITICAL"
        score = 35
        confidence = "high"
        evidence_source = "validated binary structure"
        message = "YARA matched a valid PE header in appended image payload bytes"
    condition:
        uint16(0) == 0x5A4D and
        uint32(0x3C) < filesize and
        uint32(0x3C) <= 4096 and
        uint32(uint32(0x3C)) == 0x00004550
}

rule image_appended_script_payload
{
    meta:
        finding_type = "YARA_SCRIPT_PAYLOAD"
        severity = "HIGH"
        score = 25
        confidence = "high"
        evidence_source = "validated binary structure"
        message = "YARA matched script-like payload markers in appended image bytes"
    strings:
        $php = /<\?php/i
        $script = /<script/i
        $javascript = /javascript:/i
        $eval = /eval\s*\(/i
    condition:
        any of them
}

rule image_appended_shellcode_text
{
    meta:
        finding_type = "YARA_SHELLCODE_TEXT"
        severity = "HIGH"
        score = 20
        confidence = "medium"
        evidence_source = "appended payload"
        message = "YARA matched shellcode-oriented text patterns in appended payload bytes"
    strings:
        $execve = "mov eax, 11" ascii nocase
        $int80 = "int 0x80" ascii nocase
        $socket = "mov rax, 42" ascii nocase
        $syscall = "syscall" ascii nocase
        $push2 = "push 2" ascii nocase
        $push1 = "push 1" ascii nocase
    condition:
        ($execve and $int80) or
        ($socket and $syscall) or
        ($push2 and $push1 and $syscall)
}
