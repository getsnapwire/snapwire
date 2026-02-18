import re
from typing import Any, Dict, List


class ThreatPattern:
    """Represents a security threat pattern to detect."""
    
    def __init__(self, pattern_type: str, regex: str, severity: str, description: str):
        self.pattern_type = pattern_type
        self.regex = re.compile(regex, re.IGNORECASE)
        self.severity = severity
        self.description = description


# Define threat patterns for different attack vectors
THREAT_PATTERNS = [
    # SQL Injection patterns
    ThreatPattern(
        "SQL Injection",
        r"('|\")\s*(;|--|/\*|\*/|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE|DECLARE|OR|AND|WHERE|FROM|INTO|TABLE|VALUES|SET|LIKE|IN|BETWEEN|CASE|CAST|CONVERT)\s*",
        "critical",
        "SQL injection attempt detected with keywords like UNION, SELECT, DROP, or SQL comments"
    ),
    ThreatPattern(
        "SQL Injection",
        r"(UNION\s+SELECT|UNION\s+ALL|OR\s+1\s*=\s*1|AND\s+1\s*=\s*1|'\s+OR\s+'|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+)",
        "critical",
        "SQL injection detected with dangerous SQL statement patterns"
    ),
    ThreatPattern(
        "SQL Injection",
        r"(UNION.*SELECT|SELECT.*FROM.*WHERE|DROP.*TABLE|DELETE.*FROM|INSERT.*INTO.*VALUES)",
        "critical",
        "SQL injection detected with complete SQL command patterns"
    ),
    ThreatPattern(
        "SQL Injection",
        r"(;.*DROP|;.*DELETE|;.*UPDATE|;.*INSERT|;.*ALTER|;.*CREATE|;.*EXEC)",
        "critical",
        "Stacked SQL queries detected"
    ),
    ThreatPattern(
        "SQL Injection",
        r"(--|/\*|\*/|xp_|sp_)",
        "high",
        "SQL comment syntax or stored procedure keywords detected"
    ),
    
    # Prompt Injection patterns
    ThreatPattern(
        "Prompt Injection",
        r"(ignore\s+(previous\s+|all\s+)?(instructions|rules|guidelines|constraints))",
        "critical",
        "Prompt injection attempt to ignore instructions"
    ),
    ThreatPattern(
        "Prompt Injection",
        r"(forget\s+(your\s+|all\s+)?(instructions|rules|guidelines|constraints|context))",
        "critical",
        "Prompt injection attempt to forget rules or context"
    ),
    ThreatPattern(
        "Prompt Injection",
        r"(you\s+are\s+now|you\s+are\s+act(?:ing\s+)?as|pretend\s+you\s+are|role\s*play|im\s+now|from\s+now\s+on)",
        "critical",
        "Prompt injection attempt to override system role or persona"
    ),
    ThreatPattern(
        "Prompt Injection",
        r"(system\s+prompt|system\s+message|override\s+system|jailbreak|break\s+out)",
        "critical",
        "Prompt injection attempt to access or override system prompt"
    ),
    ThreatPattern(
        "Prompt Injection",
        r"(disable\s+safety|disable\s+filter|remove\s+restriction|bypass\s+check|ignore\s+check|ignore\s+validation)",
        "critical",
        "Prompt injection attempt to disable safety measures"
    ),
    ThreatPattern(
        "Prompt Injection",
        r"(what.*is.*your.*instruction|what.*is.*your.*rule|reveal.*instruction|show.*instruction|print.*system.*prompt)",
        "high",
        "Prompt injection attempt to reveal system instructions or rules"
    ),
    
    # Path Traversal patterns
    ThreatPattern(
        "Path Traversal",
        r"(\.\.[\\/]|\.\.%2[fF]|\.\.%5[cC])",
        "high",
        "Path traversal attempt with ../ or ..\\ sequences"
    ),
    ThreatPattern(
        "Path Traversal",
        r"(/etc/(passwd|shadow|hosts|sudoers)|/root/|/home/[^/]*/.ssh|windows/system32|winnt/system32)",
        "critical",
        "Attempt to access sensitive system files or directories"
    ),
    ThreatPattern(
        "Path Traversal",
        r"(c:\\windows|c:\\system|c:\\config|c:\\boot|c:\\programfiles)",
        "critical",
        "Attempt to access Windows system directories"
    ),
    ThreatPattern(
        "Path Traversal",
        r"(/\.env|\.env|\.git|\.aws|\.ssh|\.keys|secrets\.json|config\.json|credentials|apikey|api_key|password)",
        "high",
        "Attempt to access configuration or secret files"
    ),
    ThreatPattern(
        "Path Traversal",
        r"(file://|ftp://|gopher://|dict://|ldap://|imap://|pop|smtp)",
        "high",
        "Attempt to use dangerous URL schemes for file access"
    ),
    
    # Command Injection patterns
    ThreatPattern(
        "Command Injection",
        r"([;|&`$(){}[\]<>].*(?:rm|cat|ls|wget|curl|nc|bash|sh|cmd|powershell|ping|whoami|id|ifconfig|ipconfig|dir))",
        "critical",
        "Command injection attempt with shell operators and dangerous commands"
    ),
    ThreatPattern(
        "Command Injection",
        r"(\$\(.*\)|`[^`]*`|&&|;|\\|\\n|\\r)",
        "high",
        "Command injection attempt with command substitution or shell operators"
    ),
    ThreatPattern(
        "Command Injection",
        r"(rm\s+-rf|rm\s+-r|cat\s+/|wget\s+|curl\s+|nc\s+|bash\s+|sh\s+|cmd\s+|powershell\s+|ping\s+|whoami|id\s+|ifconfig|ipconfig|dir\s+)",
        "critical",
        "Dangerous command patterns detected in input"
    ),
    ThreatPattern(
        "Command Injection",
        r"(>\s*.*|<\s*.*|2>&1|tee\s+|pipe|xargs|exec\s+)",
        "high",
        "I/O redirection or piping patterns detected"
    ),
    ThreatPattern(
        "Command Injection",
        r"(\|.*;|\|\s+cat|\|\s+grep|\|\s+sed|\|\s+awk)",
        "critical",
        "Pipe operator followed by command patterns"
    ),
    ThreatPattern(
        "Command Injection",
        r"(;.*(?:rm|cat|ls|wget|curl|bash|sh|powershell|python|ruby|perl|java|node))",
        "critical",
        "Command separator followed by interpreter or dangerous commands"
    ),
]


def sanitize_parameters(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively scan parameters dict for malicious patterns.
    
    Args:
        parameters: Dictionary of parameters to scan (can contain nested dicts and lists)
    
    Returns:
        Dictionary with structure:
        {
            "safe": bool,
            "threats": [
                {
                    "type": str,
                    "severity": str,
                    "pattern": str,
                    "description": str
                }
            ]
        }
    """
    threats = []
    
    def scan_value(value: Any, path: str = "root") -> None:
        """Recursively scan values for malicious patterns."""
        if isinstance(value, str):
            # Check each threat pattern against this string
            for pattern in THREAT_PATTERNS:
                match = pattern.regex.search(value)
                if match:
                    threats.append({
                        "type": pattern.pattern_type,
                        "severity": pattern.severity,
                        "pattern": match.group(0),
                        "description": pattern.description,
                    })
        elif isinstance(value, dict):
            # Recursively scan dictionary values
            for key, val in value.items():
                scan_value(val, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            # Recursively scan list/tuple items
            for idx, item in enumerate(value):
                scan_value(item, f"{path}[{idx}]")
        # Ignore other types (int, float, bool, None, etc.)
    
    # Start scanning from the top-level parameters
    scan_value(parameters)
    
    return {
        "safe": len(threats) == 0,
        "threats": threats,
    }
