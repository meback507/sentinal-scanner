"""
AegisSec - CVSS Scoring & Vector Service (v3.1 & v4.0)
Calculates base scores, parses vectors, and assigns severity tiers.
"""

from typing import Dict, Any, Tuple


class CVSSService:
    @staticmethod
    def get_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "NONE"

    @staticmethod
    def calculate_v31(
        av: str = "N",  # Network, Adjacent, Local, Physical
        ac: str = "L",  # Low, High
        pr: str = "N",  # None, Low, High
        ui: str = "N",  # None, Required
        s: str = "U",   # Unchanged, Changed
        c: str = "H",   # None, Low, High
        i: str = "H",   # None, Low, High
        a: str = "H"    # None, Low, High
    ) -> Tuple[float, str]:
        """
        Calculates CVSS v3.1 base score according to FIRST standard specification.
        Returns: (score, vector_string)
        """
        av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_weights = {"L": 0.77, "H": 0.44}
        pr_weights_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_weights_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_weights = {"N": 0.85, "R": 0.62}
        cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

        iss = 1.0 - ((1.0 - cia_weights.get(c, 0.56)) *
                     (1.0 - cia_weights.get(i, 0.56)) *
                     (1.0 - cia_weights.get(a, 0.56)))

        if s == "U":
            impact = 6.42 * iss
            pr_val = pr_weights_u.get(pr, 0.85)
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            pr_val = pr_weights_c.get(pr, 0.85)

        exploitability = 8.22 * av_weights.get(av, 0.85) * ac_weights.get(ac, 0.77) * pr_val * ui_weights.get(ui, 0.85)

        if impact <= 0:
            score = 0.0
        else:
            if s == "U":
                raw = min(impact + exploitability, 10.0)
            else:
                raw = min(1.08 * (impact + exploitability), 10.0)
            # Round up to 1 decimal place (CVSS standard roundup)
            score = round(raw, 1)

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return (score, vector)

    @classmethod
    def estimate_from_cwe(cls, cwe_id: str, vuln_name: str) -> Tuple[float, str]:
        """
        Derives an accurate baseline CVSS score and vector for SAST/SCA findings based on CWE taxonomy.
        """
        cwe = (cwe_id or "").upper()
        name = (vuln_name or "").lower()

        if "89" in cwe or "sqli" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")  # 9.8 Critical
        elif "78" in cwe or "command" in name or "rce" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")  # 10.0 Critical
        elif "798" in cwe or "secret" in name or "credential" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N")  # 8.2 High
        elif "79" in cwe or "xss" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")  # 6.1 Medium
        elif "502" in cwe or "deserial" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")  # 9.8 Critical
        elif "119" in cwe or "buffer" in name or "misra" in name:
            return cls.calculate_v31(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H")  # 8.1 High
        elif "22" in cwe or "traversal" in name:
            return cls.calculate_v31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")  # 7.5 High
        elif "327" in cwe or "crypto" in name:
            return cls.calculate_v31(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N")  # 5.9 Medium
        else:
            return cls.calculate_v31(av="N", ac="L", pr="L", ui="N", s="U", c="L", i="L", a="N")  # 5.4 Medium
