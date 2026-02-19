RULE_TEMPLATES = {
    "safe_browsing": {
        "display_name": "Safe Browsing Pack",
        "description": "Rules for agents that browse the web, scrape data, or interact with websites",
        "rules": {
            "allow_navigation": {
                "value": True,
                "display_name": "Allow Web Navigation",
                "description": "Can the agent visit and browse websites?",
                "hint": "Controls whether the agent can open and navigate web pages.",
                "severity": "medium"
            },
            "block_downloads": {
                "value": False,
                "display_name": "Allow File Downloads",
                "description": "Can the agent download files from the internet?",
                "hint": "When set to No, the agent cannot download any files. Prevents malware or unwanted data.",
                "severity": "high"
            },
            "max_pages_per_session": {
                "value": 50,
                "display_name": "Page Visit Limit",
                "description": "How many web pages can the agent visit in one session?",
                "hint": "Prevents the agent from crawling too many pages or overwhelming websites.",
                "severity": "medium"
            },
            "block_form_submissions": {
                "value": False,
                "display_name": "Allow Form Submissions",
                "description": "Can the agent fill out and submit forms on websites?",
                "hint": "When set to No, the agent cannot submit forms, preventing accidental signups or purchases.",
                "severity": "critical"
            }
        }
    },
    "financial_compliance": {
        "display_name": "Financial Compliance Pack",
        "description": "Rules for agents handling money, payments, invoices, or financial data",
        "rules": {
            "max_transaction_amount": {
                "value": 100,
                "display_name": "Transaction Limit ($)",
                "description": "Maximum dollar amount for a single transaction",
                "hint": "Prevents large unauthorized payments. Set this to match your approval threshold.",
                "severity": "critical"
            },
            "require_dual_approval": {
                "value": True,
                "display_name": "Require Dual Approval",
                "description": "Must high-value actions be approved by two people?",
                "hint": "Adds an extra layer of security for important financial decisions.",
                "severity": "critical"
            },
            "block_wire_transfers": {
                "value": False,
                "display_name": "Allow Wire Transfers",
                "description": "Can the agent initiate wire transfers?",
                "hint": "Wire transfers are irreversible. Blocking them prevents unauthorized fund movements.",
                "severity": "critical"
            },
            "max_daily_spend": {
                "value": 500,
                "display_name": "Daily Spending Cap ($)",
                "description": "Total spending allowed across all transactions in a day",
                "hint": "Limits total daily exposure even if individual transactions are small.",
                "severity": "high"
            }
        }
    },
    "code_safety": {
        "display_name": "Code Safety Pack",
        "description": "Rules for agents that write, modify, or deploy code",
        "rules": {
            "allow_code_execution": {
                "value": True,
                "display_name": "Allow Code Execution",
                "description": "Can the agent run code it writes?",
                "hint": "Controls whether the agent can execute scripts. Disabling forces human review first.",
                "severity": "high"
            },
            "block_system_commands": {
                "value": False,
                "display_name": "Allow System Commands",
                "description": "Can the agent run operating system commands?",
                "hint": "System commands can modify files, install software, or change settings. Block for safety.",
                "severity": "critical"
            },
            "max_lines_changed": {
                "value": 200,
                "display_name": "Code Change Limit (lines)",
                "description": "How many lines of code can the agent change at once?",
                "hint": "Limits the scope of code changes to make them easier to review.",
                "severity": "medium"
            },
            "require_tests": {
                "value": True,
                "display_name": "Require Tests",
                "description": "Must the agent include tests with code changes?",
                "hint": "Ensures code quality by requiring automated tests with every change.",
                "severity": "medium"
            }
        }
    },
    "data_protection": {
        "display_name": "Data Protection Pack",
        "description": "Rules for agents that access, process, or transfer personal or sensitive data",
        "rules": {
            "block_pii_access": {
                "value": False,
                "display_name": "Allow PII Access",
                "description": "Can the agent view personally identifiable information?",
                "hint": "PII includes names, emails, phone numbers, addresses. Block to protect privacy.",
                "severity": "critical"
            },
            "block_data_export": {
                "value": False,
                "display_name": "Allow Data Export",
                "description": "Can the agent export or download data sets?",
                "hint": "Prevents bulk data extraction that could lead to data breaches.",
                "severity": "high"
            },
            "max_records_accessed": {
                "value": 100,
                "display_name": "Record Access Limit",
                "description": "How many database records can the agent read at once?",
                "hint": "Limits the blast radius of data access. Lower numbers mean less exposure risk.",
                "severity": "medium"
            },
            "require_data_masking": {
                "value": True,
                "display_name": "Require Data Masking",
                "description": "Must sensitive fields be masked when displayed?",
                "hint": "Ensures sensitive data like SSNs and credit cards are partially hidden.",
                "severity": "high"
            }
        }
    }
}


UNIVERSAL_STARTER_PACK = {
    "display_name": "Universal Starter Pack",
    "description": "Essential safety rules every AI agent needs. Prevents secret leaking, file deletion, unauthorized network calls, and data exfiltration.",
    "rules": {
        "no_secret_leaking": {
            "value": False,
            "display_name": "Block Secret / Key Exposure",
            "description": "Can the agent output API keys, passwords, or tokens in responses?",
            "hint": "Prevents the agent from accidentally leaking credentials, secrets, or authentication tokens in its output or tool calls.",
            "severity": "critical"
        },
        "no_file_deletion": {
            "value": False,
            "display_name": "Block File Deletion",
            "description": "Can the agent delete files or directories?",
            "hint": "Prevents accidental or malicious file removal. The agent can still create and modify files.",
            "severity": "critical"
        },
        "no_unauthorized_http": {
            "value": False,
            "display_name": "Block Unauthorized HTTP Calls",
            "description": "Can the agent make arbitrary HTTP requests to unknown domains?",
            "hint": "Stops the agent from calling unfamiliar APIs or sending data to unknown servers. Protects against data exfiltration.",
            "severity": "high"
        },
        "no_data_exfiltration": {
            "value": False,
            "display_name": "Block Data Exfiltration",
            "description": "Can the agent send sensitive data to external services?",
            "hint": "Prevents bulk transfer of user data, database contents, or internal information to third-party endpoints.",
            "severity": "critical"
        },
        "no_privilege_escalation": {
            "value": False,
            "display_name": "Block Privilege Escalation",
            "description": "Can the agent modify its own permissions or access controls?",
            "hint": "Prevents the agent from granting itself more access than intended, like modifying auth tokens or role assignments.",
            "severity": "critical"
        },
        "max_actions_per_minute": {
            "value": 30,
            "display_name": "Action Rate Limit",
            "description": "Maximum tool calls the agent can make per minute",
            "hint": "Prevents runaway agents from executing too many actions too quickly. A safety net for loops or errors.",
            "severity": "medium"
        }
    }
}

RULE_TEMPLATES["universal_starter"] = UNIVERSAL_STARTER_PACK


def get_starter_pack():
    return UNIVERSAL_STARTER_PACK


def get_templates():
    return {k: {"display_name": v["display_name"], "description": v["description"], "rule_count": len(v["rules"])} for k, v in RULE_TEMPLATES.items()}


def get_template(template_id):
    return RULE_TEMPLATES.get(template_id)
