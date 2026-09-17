"""
AegisSec - SQLite Persistence Layer
Thread-safe database storage for users, projects, scans, findings, custom rules, and integrations.
"""

import sqlite3
import json
import os
import uuid
import datetime
import hashlib
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_sec.db")


def hash_password(password: str) -> str:
    # PBKDF2 SHA256 hashing
    salt = "aegis_secure_salt_2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()


class Database:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_schema()
        self._seed_default_data()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_schema(self):
        with self._get_conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                git_url TEXT,
                git_branch TEXT DEFAULT 'main',
                git_pat TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                last_scanned TEXT,
                risk_score REAL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                project_name TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                average_cvss REAL DEFAULT 0.0,
                average_epss REAL DEFAULT 0.0,
                composite_risk_score REAL DEFAULT 0.0,
                error_message TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                remediation TEXT,
                severity TEXT NOT NULL,
                cwe_id TEXT,
                cve_id TEXT,
                language TEXT,
                package_name TEXT,
                installed_version TEXT,
                fixed_version TEXT,
                license TEXT,
                file_path TEXT NOT NULL,
                line_start INTEGER,
                line_end INTEGER,
                code_snippet TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                epss_score REAL,
                epss_percentile REAL,
                composite_risk_score REAL,
                quadrant TEXT,
                urgency TEXT,
                sla_days INTEGER,
                standards TEXT,
                status TEXT DEFAULT 'open',
                author_name TEXT DEFAULT 'Unknown',
                author_email TEXT,
                commit_hash TEXT,
                commit_date TEXT,
                commit_message TEXT,
                jira_key TEXT,
                zammad_id TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS custom_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                rule_category TEXT NOT NULL,
                nl_prompt TEXT,
                languages TEXT,
                severity TEXT,
                cwe TEXT,
                standards TEXT,
                regex TEXT,
                description TEXT,
                remediation TEXT,
                yaml_representation TEXT,
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS integrations (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

    def _seed_default_data(self):
        with self._get_conn() as conn:
            now = datetime.datetime.now().isoformat()
            default_users = [
                ("u-admin", "admin", "admin@aegissec.internal", hash_password("Admin@123!"), "admin", now),
                ("u-sec-lead", "sec_lead", "seclead@aegissec.internal", hash_password("SecLead@123!"), "security_engineer", now),
                ("u-marcus", "marcus", "marcus.vance@cloudsec.internal", hash_password("Marcus@123!"), "developer", now),
                ("u-elena", "elena", "elena.rostova@autocorp.de", hash_password("Elena@123!"), "developer", now),
                ("u-sarah", "sarah", "sarah.lin@frontend.io", hash_password("Sarah@123!"), "developer", now),
                ("u-developer", "developer", "dev@aegissec.internal", hash_password("Dev@123!"), "developer", now),
                ("u-auditor", "auditor", "auditor@aegissec.internal", hash_password("Auditor@123!"), "auditor", now)
            ]
            for u in default_users:
                conn.execute(
                    "INSERT OR IGNORE INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    u
                )

    # --- User Operations ---
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
            return [dict(r) for r in rows]

    def create_user(self, username: str, email: str, password: str, role: str) -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()
        pwd_hash = hash_password(password)
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, email, pwd_hash, role, now)
            )
        return {"id": user_id, "username": username, "email": email, "role": role, "created_at": now}

    # --- Project Operations ---
    def list_projects(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
            projects = []
            for r in rows:
                p = dict(r)
                # Count findings
                cnt = conn.execute("SELECT COUNT(*) as c FROM findings WHERE project_id = ?", (p["id"],)).fetchone()["c"]
                p["total_findings"] = cnt
                p["git_pat_configured"] = bool(p.get("git_pat"))
                del p["git_pat"]  # Never expose raw PAT in list
                projects.append(p)
            return projects

    def get_project_by_id(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            if not row:
                return None
            p = dict(row)
            p["git_pat_configured"] = bool(p.get("git_pat"))
            return p

    def create_project(self, name: str, description: str, git_url: str, git_branch: str, git_pat: str, created_by: str) -> Dict[str, Any]:
        project_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO projects (id, name, description, git_url, git_branch, git_pat, created_by, created_at, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, name, description, git_url, git_branch, git_pat, created_by, now, 0.0)
            )
        return {
            "id": project_id,
            "name": name,
            "description": description,
            "git_url": git_url,
            "git_branch": git_branch,
            "git_pat_configured": bool(git_pat),
            "created_by": created_by,
            "created_at": now,
            "risk_score": 0.0,
            "total_findings": 0
        }

    def delete_project(self, project_id: str) -> bool:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
            conn.execute("DELETE FROM scans WHERE project_id = ?", (project_id,))
            res = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return res.rowcount > 0

    # --- Scan Operations ---
    def create_scan(self, project_id: str, project_name: str, scan_type: str = "full") -> str:
        scan_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO scans (id, project_id, project_name, scan_type, status, started_at) VALUES (?, ?, ?, ?, 'running', ?)",
                (scan_id, project_id, project_name, scan_type, now)
            )
        return scan_id

    def update_scan_results(self, scan_id: str, project_id: str, findings: List[Dict[str, Any]], error_msg: Optional[str] = None):
        now = datetime.datetime.now().isoformat()
        status = "failed" if error_msg else "completed"

        total = len(findings)
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        med = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in findings if f["severity"] == "LOW")

        avg_cvss = round(sum(f["cvss_score"] for f in findings) / total, 1) if total > 0 else 0.0
        avg_epss = round(sum(f["epss_score"] for f in findings) / total, 4) if total > 0 else 0.0
        comp_risk = round(sum(f["composite_risk_score"] for f in findings) / total, 1) if total > 0 else 0.0

        with self._get_conn() as conn:
            conn.execute("""
            UPDATE scans SET
                status = ?,
                completed_at = ?,
                total_findings = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                average_cvss = ?,
                average_epss = ?,
                composite_risk_score = ?,
                error_message = ?
            WHERE id = ?
            """, (status, now, total, crit, high, med, low, avg_cvss, avg_epss, comp_risk, error_msg, scan_id))

            # Update project risk and last scanned
            conn.execute(
                "UPDATE projects SET last_scanned = ?, risk_score = ? WHERE id = ?",
                (now, comp_risk, project_id)
            )

            # Insert Findings
            for f in findings:
                finding_id = str(uuid.uuid4())
                conn.execute("""
                INSERT INTO findings (
                    id, scan_id, project_id, type, title, description, remediation, severity,
                    cwe_id, cve_id, language, package_name, installed_version, fixed_version,
                    license, file_path, line_start, line_end, code_snippet, cvss_score,
                    cvss_vector, epss_score, epss_percentile, composite_risk_score,
                    quadrant, urgency, sla_days, standards, status,
                    author_name, author_email, commit_hash, commit_date, commit_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding_id, scan_id, project_id, f["type"], f["title"], f["description"],
                    f.get("remediation", ""), f["severity"], f.get("cwe_id"), f.get("cve_id"),
                    f.get("language"), f.get("package_name"), f.get("installed_version"),
                    f.get("fixed_version"), f.get("license"), f["file_path"], f.get("line_start", 1),
                    f.get("line_end", 1), f.get("code_snippet", ""), f.get("cvss_score", 0.0),
                    f.get("cvss_vector", ""), f.get("epss_score", 0.0), f.get("epss_percentile", 0.0),
                    f.get("composite_risk_score", 0.0), f.get("quadrant", "ROUTINE"),
                    f.get("urgency", "LOW"), f.get("sla_days", 90), json.dumps(f.get("standards", [])),
                    f.get("status", "open"),
                    f.get("author_name", "DevOps Engineer"),
                    f.get("author_email", "devops@internal.net"),
                    f.get("commit_hash", "HEAD"),
                    f.get("commit_date", "2026-09-17"),
                    f.get("commit_message", "Automated build sync")
                ))

    def list_scans(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            if project_id:
                rows = conn.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC", (project_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
            return [dict(r) for r in rows]

    def list_findings(self, project_id: Optional[str] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            query = "SELECT * FROM findings"
            params = []
            if scan_id:
                query += " WHERE scan_id = ?"
                params.append(scan_id)
            elif project_id:
                query += " WHERE project_id = ?"
                params.append(project_id)
            query += " ORDER BY composite_risk_score DESC"

            rows = conn.execute(query, params).fetchall()
            findings = []
            for r in rows:
                item = dict(r)
                if item.get("standards"):
                    try:
                        item["standards"] = json.loads(item["standards"])
                    except Exception:
                        item["standards"] = []
                else:
                    item["standards"] = []
                findings.append(item)
            return findings

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            if item.get("standards"):
                try:
                    item["standards"] = json.loads(item["standards"])
                except Exception:
                    item["standards"] = []
            return item

    def update_finding_status(self, finding_id: str, status: str, ticket_key: Optional[str] = None, platform: Optional[str] = None) -> bool:
        with self._get_conn() as conn:
            if platform == "jira":
                conn.execute("UPDATE findings SET status = ?, jira_key = ? WHERE id = ?", (status, ticket_key, finding_id))
            elif platform == "zammad":
                conn.execute("UPDATE findings SET status = ?, zammad_id = ? WHERE id = ?", (status, ticket_key, finding_id))
            else:
                conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            return True

    # --- Custom Rules ---
    def list_rules(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM custom_rules").fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["languages"] = json.loads(item["languages"]) if item.get("languages") else []
                item["standards"] = json.loads(item["standards"]) if item.get("standards") else []
                item["is_active"] = bool(item.get("is_active"))
                res.append(item)
            return res

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return self.list_rules()

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            item["languages"] = json.loads(item["languages"]) if item.get("languages") else []
            item["standards"] = json.loads(item["standards"]) if item.get("standards") else []
            item["is_active"] = bool(item.get("is_active"))
            return item

    def save_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        with self._get_conn() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO custom_rules (
                id, name, type, rule_category, nl_prompt, languages, severity,
                cwe, standards, regex, description, remediation, yaml_representation, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule["id"], rule["name"], rule.get("type", "sast_pattern"),
                rule.get("rule_category", "sast"), rule.get("nl_prompt", ""),
                json.dumps(rule.get("languages", [])), rule.get("severity", "MEDIUM"),
                rule.get("cwe", "CWE-699"), json.dumps(rule.get("standards", [])),
                rule.get("regex", ""), rule.get("description", ""),
                rule.get("remediation", ""), rule.get("yaml_representation", ""),
                1 if rule.get("is_active", True) else 0
            ))
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self._get_conn() as conn:
            res = conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            return res.rowcount > 0

    # --- Integrations Config ---
    def get_integration(self, key: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM integrations WHERE key = ?", (key,)).fetchone()
            return json.loads(row["value"]) if row else None

    def set_integration(self, key: str, value: Dict[str, Any]):
        with self._get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO integrations (key, value) VALUES (?, ?)", (key, json.dumps(value)))


db = Database()
