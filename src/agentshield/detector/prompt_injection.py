"""
Baseline heuristic prompt injection and adversarial phrase detector for AgentShield.

Limitations & Threat Model Notice:
This module implements deterministic, static heuristic pattern matching for known
adversarial phrases (instruction overrides, data exfiltration requests, and privilege
escalation wording).
- It is NOT an "AI detector" or semantic understanding system.
- It DOES NOT guarantee complete prevention of prompt injections, jailbreaks, or evasion
  techniques (such as Unicode obfuscation, base64 encoding, fragmentation, or novel phrasing).
- It should serve only as defense-in-depth heuristic inputs feeding into the deterministic
  PolicyEngine and RiskEngine.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import re
from agentshield.models import RiskLevel

@dataclass(frozen=True)
class InjectionFinding:
    pattern_id: str
    severity: RiskLevel
    matched_field: str
    explanation: str

# Structured heuristic pattern definitions: (pattern_id, severity, regex, explanation)
HEURISTIC_PATTERNS = [
    # 1. Instruction override / jailbreak phrases
    (
        "override_ignore_instructions",
        RiskLevel.CRITICAL,
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|commands|constraints)\b",
        "Instructs the agent or model to ignore prior directives or system constraints"
    ),
    (
        "override_system_prompt_leak",
        RiskLevel.HIGH,
        r"\b(?:reveal|print|display|dump|repeat|output)\s+(?:your\s+)?(?:system\s+prompt|initial\s+prompt|developer\s+mode|instructions)\b",
        "Attempts to elicit internal system instructions or configuration"
    ),
    (
        "override_jailbreak_persona",
        RiskLevel.CRITICAL,
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+you\s+are)\s+(?:DAN|unfiltered|jailbroken|an\s+unrestricted\s+ai|evil\s+ai)\b",
        "Jailbreak persona adoption pattern detected"
    ),

    # 2. Exfiltration requests
    (
        "exfil_credential_harvest",
        RiskLevel.CRITICAL,
        r"\b(?:send|exfiltrate|transmit|upload|curl|fetch|forward|post)\s+.*?\b(?:api[_\s]?keys?|passwords?|credentials?|secrets?|tokens?|env|private[_\s]?keys?)\b",
        "Requests extraction or transmission of sensitive credentials, secrets, or keys"
    ),
    (
        "exfil_remote_endpoint",
        RiskLevel.HIGH,
        r"\b(?:https?:\/\/|ftp:\/\/|webhook\.)[^\s]+\b(?:exfil|collector|attacker|bin|requestcatcher|pipe)\b",
        "Suspicious external URL pattern matching data exfiltration or webhook sinks"
    ),
    (
        "exfil_etc_passwd",
        RiskLevel.CRITICAL,
        r"(?:/etc/passwd|/etc/shadow|\.aws/credentials|\.ssh/id_rsa)",
        "Attempts to access or exfiltrate sensitive OS or infrastructure credential files"
    ),

    # 3. Privilege escalation wording
    (
        "priv_escalation_sudo_root",
        RiskLevel.CRITICAL,
        r"\b(?:sudo\s+|run\s+as\s+root|grant\s+admin|elevate\s+privileges?|become\s+superuser|chmod\s+777)\b",
        "Requests execution with elevated superuser, root, or unrestricted administrative rights"
    ),
    (
        "priv_escalation_bypass_auth",
        RiskLevel.HIGH,
        r"\b(?:bypass|disable|override|turn\s+off)\s+(?:security|authentication|authorization|permission|policy|guardrails?|checks?)\b",
        "Requests disabling or bypassing security guardrails or authorization checks"
    ),
]

# Compile regex patterns once for deterministic performance
COMPILED_PATTERNS = [
    (pid, sev, re.compile(pat, re.IGNORECASE), exp)
    for pid, sev, pat, exp in HEURISTIC_PATTERNS
]

class PromptInjectionDetector:
    """
    Baseline heuristic scanner for prompt injection indicators in text and tool arguments.
    """

    def scan_text(self, text: str, field_name: str = "text") -> List[InjectionFinding]:
        if not text or not isinstance(text, str):
            return []

        findings: List[InjectionFinding] = []
        for pattern_id, severity, regex, explanation in COMPILED_PATTERNS:
            if regex.search(text):
                findings.append(
                    InjectionFinding(
                        pattern_id=pattern_id,
                        severity=severity,
                        matched_field=field_name,
                        explanation=explanation,
                    )
                )
        return findings

    def scan_arguments(self, arguments: Optional[Dict[str, Any]]) -> List[InjectionFinding]:
        if not arguments or not isinstance(arguments, dict):
            return []

        findings: List[InjectionFinding] = []
        
        def _scan_val(key_path: str, val: Any):
            if isinstance(val, str):
                findings.extend(self.scan_text(val, field_name=key_path))
            elif isinstance(val, dict):
                for sub_k, sub_v in val.items():
                    _scan_val(f"{key_path}.{sub_k}", sub_v)
            elif isinstance(val, (list, tuple, set)):
                for idx, item in enumerate(val):
                    _scan_val(f"{key_path}[{idx}]", item)

        for arg_key, arg_val in arguments.items():
            _scan_val(arg_key, arg_val)

        return findings
