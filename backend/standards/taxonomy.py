"""
AegisSec - Comprehensive Standards & Compliance Taxonomy
Mappings for ISO, Automotive, Cloud, Supply Chain, and AppSec Standards.
"""

from typing import Dict, List, Any

STANDARDS_TAXONOMY: Dict[str, Dict[str, Any]] = {
    # 1. ISO Standards
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "category": "Information Security Management",
        "description": "Information security management systems requirements with Annex A controls.",
        "controls": {
            "A.8.28": "Secure Coding (Principles, threat modeling, code review, SAST)",
            "A.8.25": "Secure Development Life Cycle (Architecture, SCA, testing)",
            "A.8.8": "Management of Technical Vulnerabilities (Patching, remediation SLAs)",
            "A.8.12": "Data Leakage Prevention (Secrets in code, DLP)",
            "A.8.24": "Use of Cryptography (Ciphers, key management)"
        }
    },
    "ISO-27034": {
        "name": "ISO/IEC 27034",
        "category": "Application Security",
        "description": "Standard for developing and maintaining secure application security controls (ASC).",
        "controls": {
            "ASC-01": "Input Validation & Sanitization",
            "ASC-02": "Authentication & Session Security",
            "ASC-03": "Access Control Verification",
            "ASC-04": "Cryptographic Protection at Rest and in Transit",
            "ASC-05": "Error Handling & Diagnostic Logging"
        }
    },
    "ISO-5230": {
        "name": "ISO/IEC 5230 (OpenChain)",
        "category": "Open Source & SCA Compliance",
        "description": "International standard for open-source license compliance and SBOM management.",
        "controls": {
            "LIC-01": "Open Source License Identification & Attribution",
            "LIC-02": "Copyleft & Incompatible License Enforcing (GPL, AGPL)",
            "LIC-03": "Software Bill of Materials (SBOM) Generation"
        }
    },

    # 2. Automotive & Safety Standards
    "ISO-26262": {
        "name": "ISO 26262-6 (Functional Safety)",
        "category": "Automotive Safety (ASIL)",
        "description": "Road vehicles functional safety standard for product development at the software level.",
        "controls": {
            "Part6-Table1": "Requirements for language subset & defensive programming",
            "Part6-Table3": "Enforcement of low complexity and modular design",
            "Part6-Table7": "Static code analysis & memory safety verification",
            "ASIL-D": "Highest integrity software validation (Dynamic memory restriction, zero undefined behavior)"
        }
    },
    "ISO-21434": {
        "name": "ISO/SAE 21434:2021",
        "category": "Automotive Cybersecurity",
        "description": "Road vehicles cybersecurity engineering across development, supply chain, and post-production.",
        "controls": {
            "SecDev-01": "Cybersecurity by Design & Threat Analysis",
            "SecDev-02": "Supply Chain Vulnerability Management (Component SCA)",
            "SecDev-03": "Post-Development Vulnerability Monitoring & Patching (EPSS / CVSS triage)",
            "SecDev-04": "Zero Known Exploitable Vulnerabilities in ECU Firmware"
        }
    },
    "MISRA": {
        "name": "MISRA C:2012 / MISRA C++:2023",
        "category": "Automotive & Embedded Coding",
        "description": "Motor Industry Software Reliability Association guidelines for C and C++ safety.",
        "controls": {
            "MISRA-C:11.4": "No unsafe conversions between pointer and integer",
            "MISRA-C:17.2": "No unbounded recursion or stack overflow risks",
            "MISRA-C:21.3": "No dynamic memory allocation (malloc, calloc, free) after startup",
            "MISRA-C:22.1": "All allocated resources must be explicitly released",
            "MISRA-CPP:5.0": "Dead code elimination and control flow reachability"
        }
    },
    "AUTOSAR": {
        "name": "AUTOSAR C++14",
        "category": "Automotive Adaptive Platform",
        "description": "Guidelines for the use of the C++14 language in critical and safety-related systems.",
        "controls": {
            "A18-5-2": "Avoid non-deterministic heap memory allocations",
            "M0-1-2": "Project shall not contain unreachable code",
            "A5-1-1": "No hardcoded credentials or unvalidated external parameters"
        }
    },

    # 3. Cloud & Supply Chain Standards
    "NIST-SSDF": {
        "name": "NIST SP 800-218 (SSDF)",
        "category": "Cloud & Secure Software Development",
        "description": "Secure Software Development Framework recommendations for secure software supply chains.",
        "controls": {
            "PO.1": "Define Security Requirements for Software Development",
            "PW.1": "Design Software to Meet Security Requirements",
            "PW.5": "Configure Secure Software Build Processes",
            "PW.7": "Review and Analyze Human-Readable Code (SAST)",
            "PW.8": "Verify Third-Party Software and Dependencies (SCA)",
            "RV.1": "Identify and Confirm Vulnerabilities Continuously"
        }
    },
    "NIST-800-53": {
        "name": "NIST SP 800-53 Rev. 5",
        "category": "Federal & Cloud Security Controls",
        "description": "Security and privacy controls for information systems and cloud environments.",
        "controls": {
            "SA-11": "Developer Security Testing and Evaluation (SAST/DAST)",
            "SI-2": "Flaw Remediation and Vulnerability Patching SLA",
            "RA-5": "Vulnerability Monitoring and Threat Intelligence (CVSS/EPSS)",
            "SR-3": "Supply Chain Controls and Component Provenance (SBOM)"
        }
    },
    "CIS": {
        "name": "CIS Software Supply Chain Security",
        "category": "Cloud & Supply Chain",
        "description": "Center for Internet Security guide for source code, build pipelines, and dependencies.",
        "controls": {
            "CIS-1.1": "Prevent Hardcoded Secrets and Credentials in Version Control",
            "CIS-2.3": "Automate Dependency Vulnerability Scanning in CI/CD",
            "CIS-3.4": "Pin Dependency Versions with Cryptographic Hashes"
        }
    },
    "PCI-DSS": {
        "name": "PCI-DSS v4.0",
        "category": "Payment & Financial Security",
        "description": "Payment Card Industry Data Security Standard for protecting cardholder data.",
        "controls": {
            "Req-6.2": "Bespoke and custom software is developed securely",
            "Req-6.3": "Security vulnerabilities are identified and remediated based on risk rank",
            "Req-6.5": "Software architecture protects against OWASP / CWE common flaws"
        }
    },
    "OWASP": {
        "name": "OWASP Top 10:2021",
        "category": "General Application Security",
        "description": "Globally recognized standard awareness document for web application vulnerabilities.",
        "controls": {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection (SQL, Command, LDAP)",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components (SCA)",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery (SSRF)"
        }
    },
    "CWE": {
        "name": "CWE / SANS Top 25",
        "category": "Common Weakness Enumeration",
        "description": "Most widespread and dangerous software weaknesses.",
        "controls": {
            "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
            "CWE-89": "Improper Neutralization of Special Elements in SQL Command (SQLi)",
            "CWE-78": "Improper Neutralization of OS Command Elements",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-416": "Use After Free",
            "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory"
        }
    }
}


def map_finding_to_standards(cwe_id: str, vuln_type: str, category: str = "") -> List[str]:
    """
    Automatically associates a vulnerability finding with appropriate multi-standard tags.
    """
    standards: List[str] = []
    cwe = (cwe_id or "").upper()
    vtype = (vuln_type or "").lower()

    # Secret / Credential Leaks
    if "798" in cwe or "secret" in vtype or "token" in vtype or "credential" in vtype or "key" in vtype:
        standards.extend([
            "ISO-27001:A.8.28",
            "ISO-27001:A.8.12",
            "NIST-SSDF:PW.7",
            "CIS:CIS-1.1",
            "OWASP:A07:2021",
            "PCI-DSS:Req-6.2",
            "AUTOSAR:A5-1-1"
        ])

    # Injections (SQLi, Command Injection, etc.)
    elif "89" in cwe or "78" in cwe or "injection" in vtype or "sqli" in vtype:
        standards.extend([
            "OWASP:A03:2021",
            "ISO-27034:ASC-01",
            "ISO-27001:A.8.28",
            "NIST-SSDF:PW.7",
            "PCI-DSS:Req-6.5",
            "ISO-21434:SecDev-01"
        ])

    # Memory / Buffer / Safety (Automotive & C/C++)
    elif "119" in cwe or "416" in cwe or "buffer" in vtype or "memory" in vtype or "overflow" in vtype or "misra" in vtype:
        standards.extend([
            "ISO-26262:Part6-Table7",
            "ISO-26262:ASIL-D",
            "ISO-21434:SecDev-01",
            "MISRA:MISRA-C:21.3",
            "AUTOSAR:A18-5-2",
            "CWE:CWE-119"
        ])

    # Cryptography
    elif "327" in cwe or "crypto" in vtype or "cipher" in vtype or "hash" in vtype:
        standards.extend([
            "ISO-27001:A.8.24",
            "OWASP:A02:2021",
            "NIST-800-53:SA-11",
            "PCI-DSS:Req-6.5"
        ])

    # Dependency / SCA / Outdated Components
    elif "sca" in vtype or "dependency" in vtype or "cve" in vtype or "1104" in cwe:
        standards.extend([
            "OWASP:A06:2021",
            "NIST-SSDF:PW.8",
            "NIST-800-53:SR-3",
            "ISO-27001:A.8.25",
            "ISO-5230:LIC-01",
            "ISO-21434:SecDev-02",
            "CIS:CIS-2.3"
        ])

    # Insecure Deserialization
    elif "502" in cwe or "deserial" in vtype:
        standards.extend([
            "OWASP:A08:2021",
            "CWE:CWE-502",
            "ISO-27001:A.8.28",
            "NIST-SSDF:PW.7"
        ])

    # Path Traversal
    elif "22" in cwe or "traversal" in vtype:
        standards.extend([
            "OWASP:A01:2021",
            "CWE:CWE-22",
            "ISO-27034:ASC-01"
        ])

    # Default fallback
    else:
        standards.extend([
            "ISO-27001:A.8.28",
            "NIST-SSDF:PW.7",
            "OWASP:A04:2021"
        ])

    return list(dict.fromkeys(standards))  # deduplicate preserving order
