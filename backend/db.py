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
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

DB_FILE = os.getenv("SENTINEL_DB_PATH") or os.getenv("DATABASE_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_sec.db")


def hash_password(password: str) -> str:
    # PBKDF2 SHA256 hashing
    salt = "aegis_secure_salt_2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()


def compute_finding_fingerprint(project_id: str, f: Dict[str, Any]) -> str:
    """
    Computes a deterministic unique fingerprint for a finding within a project.
    Prevents duplicate findings from being recreated across repeated scans.
    """
    ftype = (f.get("type") or f.get("scan_type") or "sast").strip().lower()
    fpath = (f.get("file_path") or "").strip().replace("\\", "/")

    if ftype == "sca":
        pkg = (f.get("package_name") or "").strip().lower()
        cve = (f.get("cve_id") or f.get("title") or "").strip().upper()
        raw = f"{project_id}:sca:{fpath}:{pkg}:{cve}"
    else:
        # SAST or Secret
        cwe = (f.get("cwe_id") or "").strip().upper()
        title = (f.get("title") or "").strip().lower()
        line_start = str(f.get("line_start", 1))
        raw = f"{project_id}:{ftype}:{fpath}:{cwe}:{title}:{line_start}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def parse_date_safely(date_str: Optional[str]) -> Optional[datetime.datetime]:
    """
    Parses various date/time formats robustly.
    """
    if not date_str or str(date_str).strip() in ("N/A", "Unknown", "None", ""):
        return None
    date_str = str(date_str).strip()
    try:
        return datetime.datetime.fromisoformat(date_str)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except Exception:
            pass
    return None


def enrich_finding_age(finding: Dict[str, Any], current_time: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """
    Calculates dynamic vulnerability age and formatted first_seen date.
    """
    now = current_time or datetime.datetime.now()
    fs_str = finding.get("first_seen") or finding.get("commit_date")
    fs_dt = parse_date_safely(fs_str)

    if not fs_dt:
        fs_dt = now
        fs_str = now.isoformat()
        finding["first_seen"] = fs_str

    diff_days = max(0, (now.date() - fs_dt.date()).days)

    finding["first_seen"] = fs_str
    finding["first_seen_date"] = fs_dt.strftime("%Y-%m-%d")
    finding["age_days"] = diff_days

    if diff_days == 0:
        finding["age_display"] = "Today (< 24h)"
    elif diff_days == 1:
        finding["age_display"] = "1 day old"
    else:
        finding["age_display"] = f"{diff_days} days old"

    return finding


class Database:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.getenv("SENTINEL_DB_PATH") or os.getenv("DATABASE_PATH") or DB_FILE
        try:
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            self._init_schema()
            self._seed_default_data()
        except Exception as e:
            fallback = "/tmp/sentinel.db"
            if self.db_path != fallback:
                print(f"[Sentinel DB] Warning: Cannot initialize database at {self.db_path} ({e}). Falling back to {fallback}")
                self.db_path = fallback
                self._init_schema()
                self._seed_default_data()
            else:
                raise

    @contextmanager
    def _get_conn(self):
        conn = None
        try:
            with self._db_connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA foreign_keys = ON;")
                yield conn
        except sqlite3.OperationalError as e:
            fallback = "/tmp/sentinel.db"
            if self.db_path != fallback:
                print(f"[Sentinel DB] Warning: Connection error on {self.db_path} ({e}). Falling back to {fallback}")
                self.db_path = fallback
                with self._db_connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA foreign_keys = ON;")
                    yield conn
            else:
                raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    _db_connect = getattr(sqlite3, "connect")

    def get_connection(self) -> sqlite3.Connection:
        """Provides an active database connection for direct SQL execution."""
        conn = self._db_connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
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
                ticket_assigned_to TEXT,
                ticket_assigned_email TEXT,
                first_seen TEXT,
                last_seen TEXT,
                fingerprint TEXT,
                cisa_kev INTEGER DEFAULT 0,
                cisa_kev_due_date TEXT,
                ai_confidence_score REAL,
                ai_confidence_label TEXT,
                ai_confidence_rationale TEXT,
                dependency_lag_versions TEXT,
                reachability_status TEXT DEFAULT 'UNKNOWN',
                entropy REAL,
                masked_value TEXT,
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
                is_active INTEGER DEFAULT 1,
                project_id TEXT,
                project_name TEXT
            );

            CREATE TABLE IF NOT EXISTS integrations (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                finding_id TEXT,
                project_id TEXT,
                user TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                cryptographic_seal TEXT NOT NULL
            );
            """)

            # Automatic schema migration for existing SQLite databases
            try:
                cols = [c[1] for c in conn.execute("PRAGMA table_info(findings)").fetchall()]
                if "ticket_assigned_to" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN ticket_assigned_to TEXT")
                if "ticket_assigned_email" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN ticket_assigned_email TEXT")
                if "first_seen" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN first_seen TEXT")
                if "last_seen" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN last_seen TEXT")
                if "fingerprint" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
                if "cisa_kev" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN cisa_kev INTEGER DEFAULT 0")
                if "cisa_kev_due_date" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN cisa_kev_due_date TEXT")
                if "ai_confidence_score" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN ai_confidence_score REAL")
                if "ai_confidence_label" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN ai_confidence_label TEXT")
                if "ai_confidence_rationale" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN ai_confidence_rationale TEXT")
                if "dependency_lag_versions" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN dependency_lag_versions TEXT")
                if "reachability_status" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN reachability_status TEXT DEFAULT 'UNKNOWN'")
                if "entropy" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN entropy REAL")
                if "masked_value" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN masked_value TEXT")
                self._migrate_and_deduplicate_findings(conn)

                # Migration for project-scoped custom rules
                rule_cols = [c[1] for c in conn.execute("PRAGMA table_info(custom_rules)").fetchall()]
                if "project_id" not in rule_cols:
                    conn.execute("ALTER TABLE custom_rules ADD COLUMN project_id TEXT")
                if "project_name" not in rule_cols:
                    conn.execute("ALTER TABLE custom_rules ADD COLUMN project_name TEXT")

                # Migration for project members / user assignments
                conn.executescript("""
                CREATE TABLE IF NOT EXISTS project_members (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    assigned_at TEXT NOT NULL,
                    UNIQUE(project_id, user_id)
                );
                CREATE INDEX IF NOT EXISTS idx_pm_project ON project_members(project_id);
                CREATE INDEX IF NOT EXISTS idx_pm_user ON project_members(user_id);
                """)
            except Exception:
                pass

    def _migrate_and_deduplicate_findings(self, conn: sqlite3.Connection):
        """
        Backfills fingerprint, first_seen, and last_seen for existing database rows,
        purges orphan records from deleted projects, and removes duplicate finding rows.
        """
        try:
            # Purge orphan records from projects that were deleted
            conn.execute("DELETE FROM findings WHERE project_id NOT IN (SELECT id FROM projects)")
            conn.execute("DELETE FROM scans WHERE project_id NOT IN (SELECT id FROM projects)")

            rows = conn.execute("SELECT * FROM findings").fetchall()
            if not rows:
                return

            now = datetime.datetime.now().isoformat()
            seen = {}
            for r in rows:
                item = dict(r)
                pid = item.get("project_id", "")
                fp = item.get("fingerprint")
                if not fp:
                    fp = compute_finding_fingerprint(pid, item)
                    conn.execute("UPDATE findings SET fingerprint = ? WHERE id = ?", (fp, item["id"]))
                    item["fingerprint"] = fp

                fs = item.get("first_seen")
                if not fs:
                    fs = item.get("commit_date") or now
                    conn.execute("UPDATE findings SET first_seen = ?, last_seen = ? WHERE id = ?", (fs, fs, item["id"]))
                    item["first_seen"] = fs
                    item["last_seen"] = fs

                key = (pid, fp)
                if key in seen:
                    # Duplicate found in historical data: preserve ticket if present, delete redundant row
                    prev = seen[key]
                    has_ticket_curr = bool(item.get("jira_key") or item.get("zammad_id") or item.get("ticket_assigned_to"))
                    has_ticket_prev = bool(prev.get("jira_key") or prev.get("zammad_id") or prev.get("ticket_assigned_to"))

                    if has_ticket_curr and not has_ticket_prev:
                        conn.execute("DELETE FROM findings WHERE id = ?", (prev["id"],))
                        seen[key] = item
                    else:
                        conn.execute("DELETE FROM findings WHERE id = ?", (item["id"],))
                else:
                    seen[key] = item
        except Exception:
            pass

    def _seed_default_data(self):
        with self._get_conn() as conn:
            now = datetime.datetime.now().isoformat()
            admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
            admin_password = os.getenv("ADMIN_PASSWORD") or os.getenv("SENTINEL_ADMIN_PASSWORD") or "admin"
            admin_email = os.getenv("ADMIN_EMAIL", f"{admin_username}@sentinel.internal").strip()

            # Remove all test/demo users - ONLY the single admin user exists
            conn.execute("DELETE FROM users WHERE username != ?", (admin_username,))

            # Upsert the configured default admin user
            admin_user = conn.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone()
            if not admin_user:
                conn.execute(
                    "INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    ("u-admin", admin_username, admin_email, hash_password(admin_password), "admin", now)
                )
            else:
                conn.execute(
                    "UPDATE users SET password_hash = ?, email = ?, role = 'admin' WHERE username = ?",
                    (hash_password(admin_password), admin_email, admin_username)
                )

            # Remove all demo/test projects and related test data
            conn.execute("DELETE FROM findings WHERE project_id IN (SELECT id FROM projects WHERE name LIKE '%Demo%' OR git_url = '' OR git_url = 'demo')")
            conn.execute("DELETE FROM scans WHERE project_id IN (SELECT id FROM projects WHERE name LIKE '%Demo%' OR git_url = '' OR git_url = 'demo')")
            conn.execute("DELETE FROM projects WHERE name LIKE '%Demo%' OR git_url = '' OR git_url = 'demo'")

    # --- User Operations ---
    def _get_user_assigned_projects_conn(self, conn: sqlite3.Connection, user_id_or_username: str) -> List[str]:
        """Returns assigned project IDs using an active connection."""
        user = conn.execute("SELECT id, username FROM users WHERE id = ? OR username = ?", (user_id_or_username, user_id_or_username)).fetchone()
        actual_id = user["id"] if user else user_id_or_username
        actual_username = user["username"] if user else user_id_or_username
        rows = conn.execute(
            "SELECT DISTINCT project_id FROM project_members WHERE user_id = ? OR user_id = ?",
            (actual_id, actual_username)
        ).fetchall()
        return [r["project_id"] for r in rows if r["project_id"]]

    def _get_project_members_conn(self, conn: sqlite3.Connection, project_id: str) -> List[Dict[str, Any]]:
        """Returns assigned project members using an active connection."""
        rows = conn.execute("""
            SELECT pm.user_id, pm.role as project_role, pm.assigned_at,
                   u.username, u.email, u.role as system_role
            FROM project_members pm
            LEFT JOIN users u ON (u.id = pm.user_id OR u.username = pm.user_id)
            WHERE pm.project_id = ?
            ORDER BY pm.assigned_at ASC
        """, (project_id,)).fetchall()
        members = []
        for r in rows:
            m = dict(r)
            members.append({
                "user_id": m["user_id"],
                "username": m.get("username") or m["user_id"],
                "email": m.get("email") or f"{m['user_id']}@sentinel.internal",
                "system_role": m.get("system_role") or "developer",
                "project_role": m.get("project_role") or "member",
                "assigned_at": m.get("assigned_at")
            })
        return members

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return None
            u = dict(row)
            u["assigned_projects"] = self._get_user_assigned_projects_conn(conn, u["id"])
            return u

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            if not row:
                return None
            u = dict(row)
            u["assigned_projects"] = self._get_user_assigned_projects_conn(conn, u["id"])
            return u

    def list_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at ASC").fetchall()
            users = []
            for r in rows:
                u = dict(r)
                u["assigned_projects"] = self._get_user_assigned_projects_conn(conn, u["id"])
                users.append(u)
            return users

    def create_user(self, username: str, email: str, password: str, role: str, assigned_projects: Optional[List[str]] = None) -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()
        pwd_hash = hash_password(password)
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, email, pwd_hash, role, now)
            )
        if assigned_projects:
            self.set_user_projects(user_id, assigned_projects)
        return {
            "id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "created_at": now,
            "assigned_projects": assigned_projects or []
        }

    def update_user(self, user_id: str, role: Optional[str] = None, password: Optional[str] = None, email: Optional[str] = None, assigned_projects: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            if not user:
                return None
            actual_id = user["id"]
            
            updates = []
            params = []
            if role:
                updates.append("role = ?")
                params.append(role)
            if password:
                updates.append("password_hash = ?")
                params.append(hash_password(password))
            if email:
                updates.append("email = ?")
                params.append(email)
            
            if updates:
                params.append(actual_id)
                query_sql = "UPDATE users SET " + ", ".join(updates) + " WHERE id = ?"
                conn.execute(query_sql, tuple(params))
            
            row = conn.execute("SELECT id, username, email, role, created_at FROM users WHERE id = ?", (actual_id,)).fetchone()
            if not row:
                return None
            res = dict(row)

        if assigned_projects is not None:
            self.set_user_projects(actual_id, assigned_projects)
        res["assigned_projects"] = self.get_user_assigned_projects(actual_id)
        return res

    def delete_user(self, user_id: str) -> bool:
        with self._get_conn() as conn:
            user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            actual_id = user["id"] if user else user_id
            conn.execute("DELETE FROM project_members WHERE user_id = ? OR user_id = ?", (actual_id, user_id))
            cur = conn.execute("DELETE FROM users WHERE id = ? OR username = ?", (user_id, user_id))
            return cur.rowcount > 0

    # --- Project Membership Operations ---
    def assign_user_to_project(self, project_id: str, user_id: str, role: Optional[str] = "member") -> bool:
        """Assigns a user to a specific project scope."""
        with self._get_conn() as conn:
            user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            actual_id = user["id"] if user else user_id
            now = datetime.datetime.now().isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO project_members (id, project_id, user_id, role, assigned_at) VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), project_id, actual_id, role or "member", now)
            )
            return True

    def remove_user_from_project(self, project_id: str, user_id: str) -> bool:
        """Removes a user from a specific project scope."""
        with self._get_conn() as conn:
            user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            actual_id = user["id"] if user else user_id
            cur = conn.execute(
                "DELETE FROM project_members WHERE project_id = ? AND (user_id = ? OR user_id = ?)",
                (project_id, actual_id, user_id)
            )
            return cur.rowcount > 0

    def set_user_projects(self, user_id: str, project_ids: List[str]) -> bool:
        """Sets the exact list of projects a user is assigned to."""
        with self._get_conn() as conn:
            user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (user_id, user_id)).fetchone()
            actual_id = user["id"] if user else user_id
            conn.execute("DELETE FROM project_members WHERE user_id = ? OR user_id = ?", (actual_id, user_id))
            now = datetime.datetime.now().isoformat()
            for pid in project_ids:
                if pid:
                    conn.execute(
                        "INSERT OR REPLACE INTO project_members (id, project_id, user_id, role, assigned_at) VALUES (?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), pid.strip(), actual_id, "member", now)
                    )
            return True

    def set_project_members(self, project_id: str, user_ids: List[str]) -> bool:
        """Sets the exact list of users assigned to a project."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM project_members WHERE project_id = ?", (project_id,))
            now = datetime.datetime.now().isoformat()
            for uid in user_ids:
                if uid:
                    user = conn.execute("SELECT id FROM users WHERE id = ? OR username = ?", (uid, uid)).fetchone()
                    actual_id = user["id"] if user else uid
                    conn.execute(
                        "INSERT OR REPLACE INTO project_members (id, project_id, user_id, role, assigned_at) VALUES (?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), project_id, actual_id, "member", now)
                    )
            return True

    def get_user_assigned_projects(self, user_id_or_username: str) -> List[str]:
        """Returns the list of project IDs explicitly assigned to a user."""
        with self._get_conn() as conn:
            return self._get_user_assigned_projects_conn(conn, user_id_or_username)

    def get_project_members(self, project_id: str) -> List[Dict[str, Any]]:
        """Returns the list of users assigned to a project with their roles and assignment timestamps."""
        with self._get_conn() as conn:
            return self._get_project_members_conn(conn, project_id)

    def get_projects_with_user_findings(self, username: str, email: Optional[str] = None) -> List[str]:
        """Finds projects where a developer has authored code flaws (used for test/demo backwards compatibility)."""
        with self._get_conn() as conn:
            params = [f"%{username.lower()}%"]
            query = "SELECT DISTINCT project_id FROM findings WHERE LOWER(author_name) LIKE ?"
            if email:
                query += " OR LOWER(author_email) = ?"
                params.append(email.lower())
            rows = conn.execute(query, tuple(params)).fetchall()
            return [r["project_id"] for r in rows if r["project_id"]]

    # --- Project Operations ---
    def list_projects(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
            projects = []
            for r in rows:
                p = dict(r)
                # Count findings (active non-resolved)
                cnt = conn.execute("SELECT COUNT(*) as c FROM findings WHERE project_id = ? AND status != 'resolved'", (p["id"],)).fetchone()["c"]
                p["total_findings"] = cnt
                p["git_pat_configured"] = bool(p.get("git_pat"))
                del p["git_pat"]  # Never expose raw PAT in list
                members = self._get_project_members_conn(conn, p["id"])
                p["members"] = members
                p["member_count"] = len(members)
                projects.append(p)
            return projects

    def get_project_by_id(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            if not row:
                return None
            p = dict(row)
            p["git_pat_configured"] = bool(p.get("git_pat"))
            cnt = conn.execute("SELECT COUNT(*) as c FROM findings WHERE project_id = ? AND status != 'resolved'", (project_id,)).fetchone()["c"]
            p["total_findings"] = cnt
            members = self._get_project_members_conn(conn, project_id)
            p["members"] = members
            p["member_count"] = len(members)
            return p

    def create_project(self, name: str, description: str, git_url: str, git_branch: str, git_pat: str, created_by: str, assigned_users: Optional[List[str]] = None) -> Dict[str, Any]:
        project_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO projects (id, name, description, git_url, git_branch, git_pat, created_by, created_at, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, name, description, git_url, git_branch, git_pat, created_by, now, 0.0)
            )
        
        # Assign creator if non-admin or explicit
        if created_by and created_by != "admin":
            self.assign_user_to_project(project_id, created_by, role="lead")
        
        if assigned_users:
            for uid in assigned_users:
                if uid:
                    self.assign_user_to_project(project_id, uid, role="member")

        members = self.get_project_members(project_id)
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
            "total_findings": 0,
            "members": members,
            "member_count": len(members)
        }

    def delete_project(self, project_id: str) -> bool:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM project_members WHERE project_id = ?", (project_id,))
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

        with self._get_conn() as conn:
            if error_msg:
                conn.execute("""
                UPDATE scans SET
                    status = ?,
                    completed_at = ?,
                    error_message = ?
                WHERE id = ?
                """, (status, now, error_msg, scan_id))
                return

            # Fetch existing findings for this project to deduplicate
            existing_rows = conn.execute("SELECT * FROM findings WHERE project_id = ?", (project_id,)).fetchall()
            existing_by_fp = {}
            for r in existing_rows:
                r_dict = dict(r)
                fp = r_dict.get("fingerprint")
                if not fp:
                    fp = compute_finding_fingerprint(project_id, r_dict)
                    conn.execute("UPDATE findings SET fingerprint = ? WHERE id = ?", (fp, r_dict["id"]))
                    r_dict["fingerprint"] = fp

                # Deduplicate existing historical records if any
                if fp in existing_by_fp:
                    prev = existing_by_fp[fp]
                    has_ticket_curr = bool(r_dict.get("jira_key") or r_dict.get("zammad_id") or r_dict.get("ticket_assigned_to"))
                    has_ticket_prev = bool(prev.get("jira_key") or prev.get("zammad_id") or prev.get("ticket_assigned_to"))
                    if has_ticket_curr and not has_ticket_prev:
                        conn.execute("DELETE FROM findings WHERE id = ?", (prev["id"],))
                        existing_by_fp[fp] = r_dict
                    else:
                        conn.execute("DELETE FROM findings WHERE id = ?", (r_dict["id"],))
                else:
                    existing_by_fp[fp] = r_dict

            incoming_fingerprints = set()

            for f in findings:
                fp = compute_finding_fingerprint(project_id, f)
                f["fingerprint"] = fp
                incoming_fingerprints.add(fp)

                ftype = f.get("type") or f.get("scan_type") or "sast"
                title = f.get("title", "")
                description = f.get("description", "")
                remediation = f.get("remediation", "")
                severity = f.get("severity", "MEDIUM")
                cwe_id = f.get("cwe_id")
                cve_id = f.get("cve_id")
                language = f.get("language")
                package_name = f.get("package_name")
                installed_version = f.get("installed_version")
                fixed_version = f.get("fixed_version")
                license_val = f.get("license")
                file_path = f.get("file_path", "")
                line_start = f.get("line_start", 1)
                line_end = f.get("line_end", 1)
                code_snippet = f.get("code_snippet", "")
                cvss_score = f.get("cvss_score", 0.0)
                cvss_vector = f.get("cvss_vector", "")
                epss_score = f.get("epss_score", 0.0)
                epss_percentile = f.get("epss_percentile", 0.0)
                composite_risk_score = f.get("composite_risk_score", 0.0)
                quadrant = f.get("quadrant", "ROUTINE")
                urgency = f.get("urgency", "LOW")
                sla_days = f.get("sla_days", 90)
                standards = json.dumps(f.get("standards", []))

                cisa_kev_val = 1 if f.get("cisa_kev") else 0
                cisa_kev_due_date = f.get("cisa_kev_due_date")
                ai_confidence_score = f.get("ai_confidence_score")
                ai_confidence_label = f.get("ai_confidence_label")
                ai_confidence_rationale = f.get("ai_confidence_rationale")
                dependency_lag_versions = f.get("dependency_lag_versions")
                reachability_status = f.get("reachability_status") or f.get("reachability") or "UNKNOWN"
                entropy_val = f.get("entropy")
                masked_val = f.get("masked_value")

                if fp in existing_by_fp:
                    # Repeating vulnerability: DO NOT re-create new row!
                    existing = existing_by_fp[fp]
                    finding_id = existing["id"]

                    # Preserve first_seen
                    orig_first_seen = existing.get("first_seen") or existing.get("commit_date") or now

                    # If it was resolved, re-open since scanner detected it again
                    curr_status = existing.get("status", "open")
                    if curr_status == "resolved":
                        curr_status = "open"

                    # Preserve ticket assignments
                    jira_key = existing.get("jira_key") or f.get("jira_key")
                    zammad_id = existing.get("zammad_id") or f.get("zammad_id")
                    ticket_assigned_to = existing.get("ticket_assigned_to") or f.get("ticket_assigned_to")
                    ticket_assigned_email = existing.get("ticket_assigned_email") or f.get("ticket_assigned_email")

                    author_name = f.get("author_name") or existing.get("author_name", "DevOps Engineer")
                    author_email = f.get("author_email") or existing.get("author_email", "devops@internal.net")
                    commit_hash = f.get("commit_hash") or existing.get("commit_hash", "HEAD")
                    commit_date = f.get("commit_date") or existing.get("commit_date", "2026-09-17")
                    commit_message = f.get("commit_message") or existing.get("commit_message", "Automated build sync")

                    # Keep existing AI confidence if not re-evaluated
                    if ai_confidence_score is None and existing.get("ai_confidence_score") is not None:
                        ai_confidence_score = existing.get("ai_confidence_score")
                        ai_confidence_label = existing.get("ai_confidence_label")
                        ai_confidence_rationale = existing.get("ai_confidence_rationale")

                    conn.execute("""
                    UPDATE findings SET
                        scan_id = ?,
                        type = ?,
                        title = ?,
                        description = ?,
                        remediation = ?,
                        severity = ?,
                        cwe_id = ?,
                        cve_id = ?,
                        language = ?,
                        package_name = ?,
                        installed_version = ?,
                        fixed_version = ?,
                        license = ?,
                        file_path = ?,
                        line_start = ?,
                        line_end = ?,
                        code_snippet = ?,
                        cvss_score = ?,
                        cvss_vector = ?,
                        epss_score = ?,
                        epss_percentile = ?,
                        composite_risk_score = ?,
                        quadrant = ?,
                        urgency = ?,
                        sla_days = ?,
                        standards = ?,
                        status = ?,
                        author_name = ?,
                        author_email = ?,
                        commit_hash = ?,
                        commit_date = ?,
                        commit_message = ?,
                        jira_key = ?,
                        zammad_id = ?,
                        ticket_assigned_to = ?,
                        ticket_assigned_email = ?,
                        first_seen = ?,
                        last_seen = ?,
                        fingerprint = ?,
                        cisa_kev = ?,
                        cisa_kev_due_date = ?,
                        ai_confidence_score = ?,
                        ai_confidence_label = ?,
                        ai_confidence_rationale = ?,
                        dependency_lag_versions = ?,
                        reachability_status = ?,
                        entropy = ?,
                        masked_value = ?
                    WHERE id = ?
                    """, (
                        scan_id, ftype, title, description, remediation, severity,
                        cwe_id, cve_id, language, package_name, installed_version, fixed_version,
                        license_val, file_path, line_start, line_end, code_snippet, cvss_score,
                        cvss_vector, epss_score, epss_percentile, composite_risk_score,
                        quadrant, urgency, sla_days, standards, curr_status,
                        author_name, author_email, commit_hash, commit_date, commit_message,
                        jira_key, zammad_id, ticket_assigned_to, ticket_assigned_email,
                        orig_first_seen, now, fp,
                        cisa_kev_val, cisa_kev_due_date, ai_confidence_score, ai_confidence_label,
                        ai_confidence_rationale, dependency_lag_versions, reachability_status,
                        entropy_val, masked_val,
                        finding_id
                    ))
                else:
                    # New vulnerability introduced or discovered
                    finding_id = str(uuid.uuid4())
                    first_seen = f.get("first_seen") or f.get("commit_date") or now
                    author_name = f.get("author_name", "DevOps Engineer")
                    author_email = f.get("author_email", "devops@internal.net")
                    commit_hash = f.get("commit_hash", "HEAD")
                    commit_date = f.get("commit_date", "2026-09-17")
                    commit_message = f.get("commit_message", "Automated build sync")

                    conn.execute("""
                    INSERT INTO findings (
                        id, scan_id, project_id, type, title, description, remediation, severity,
                        cwe_id, cve_id, language, package_name, installed_version, fixed_version,
                        license, file_path, line_start, line_end, code_snippet, cvss_score,
                        cvss_vector, epss_score, epss_percentile, composite_risk_score,
                        quadrant, urgency, sla_days, standards, status,
                        author_name, author_email, commit_hash, commit_date, commit_message,
                        jira_key, zammad_id, ticket_assigned_to, ticket_assigned_email,
                        first_seen, last_seen, fingerprint,
                        cisa_kev, cisa_kev_due_date, ai_confidence_score, ai_confidence_label,
                        ai_confidence_rationale, dependency_lag_versions, reachability_status,
                        entropy, masked_value
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        finding_id, scan_id, project_id, ftype, title, description, remediation, severity,
                        cwe_id, cve_id, language, package_name, installed_version, fixed_version,
                        license_val, file_path, line_start, line_end, code_snippet, cvss_score,
                        cvss_vector, epss_score, epss_percentile, composite_risk_score,
                        quadrant, urgency, sla_days, standards, f.get("status", "open"),
                        author_name, author_email, commit_hash, commit_date, commit_message,
                        f.get("jira_key"), f.get("zammad_id"), f.get("ticket_assigned_to"), f.get("ticket_assigned_email"),
                        first_seen, now, fp,
                        cisa_kev_val, cisa_kev_due_date, ai_confidence_score, ai_confidence_label,
                        ai_confidence_rationale, dependency_lag_versions, reachability_status,
                        entropy_val, masked_val
                    ))

            # Determine scan_type to scope auto-resolve strictly to covered finding types
            scan_row = conn.execute("SELECT scan_type FROM scans WHERE id = ?", (scan_id,)).fetchone()
            scan_type = "full"
            if scan_row:
                try:
                    scan_type = (scan_row["scan_type"] or "full").lower()
                except (IndexError, KeyError):
                    scan_type = "full"

            SCAN_TYPE_MAP = {
                "full": {"sast", "sca", "secret", "iac", "api"},
                "secrets": {"secret"},
                "sca": {"sca"},
                "sast": {"sast", "secret", "iac", "api"},
                "iac": {"iac"},
                "api": {"api"}
            }
            covered_types = SCAN_TYPE_MAP.get(scan_type, {"sast", "sca", "secret", "iac", "api"})

            # Auto-resolve vulnerabilities that were not detected in this scan,
            # scoping strictly to finding types that were part of this scan.
            for fp, ex in existing_by_fp.items():
                ex_type = (ex.get("type") or "sast").lower()
                if ex_type not in covered_types:
                    # Do not touch findings from engines that did not run in this scan
                    continue
                if fp not in incoming_fingerprints:
                    if ex.get("status") in ("open", "in_triage", "confirmed"):
                        conn.execute("UPDATE findings SET status = 'resolved', last_seen = ? WHERE id = ?", (now, ex["id"]))

            # Compute accurate scan & project metrics on active (non-resolved) findings
            active_rows = conn.execute(
                "SELECT severity, cvss_score, epss_score, composite_risk_score FROM findings WHERE project_id = ? AND status != 'resolved'",
                (project_id,)
            ).fetchall()

            total = len(active_rows)
            crit = sum(1 for r in active_rows if r["severity"] == "CRITICAL")
            high = sum(1 for r in active_rows if r["severity"] == "HIGH")
            med = sum(1 for r in active_rows if r["severity"] == "MEDIUM")
            low = sum(1 for r in active_rows if r["severity"] == "LOW")
            avg_cvss = round(sum(r["cvss_score"] for r in active_rows) / total, 1) if total > 0 else 0.0
            avg_epss = round(sum(r["epss_score"] for r in active_rows) / total, 4) if total > 0 else 0.0
            comp_risk = round(sum(r["composite_risk_score"] for r in active_rows) / total, 1) if total > 0 else 0.0

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

    def list_scans(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            if project_id:
                rows = conn.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC", (project_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
            return [dict(r) for r in rows]

    def create_finding(self, f: Dict[str, Any]) -> Dict[str, Any]:
        with self._get_conn() as conn:
            now = datetime.datetime.now().isoformat()
            fid = f.get("id") or str(uuid.uuid4())
            pid = f.get("project_id", "")
            scan_id = f.get("scan_id")
            if not scan_id or scan_id == "scan-manual":
                s_row = conn.execute("SELECT id FROM scans WHERE project_id = ? ORDER BY started_at DESC LIMIT 1", (pid,)).fetchone()
                if s_row:
                    scan_id = s_row["id"]
                else:
                    scan_id = str(uuid.uuid4())
                    conn.execute(
                        "INSERT OR IGNORE INTO scans (id, project_id, project_name, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (scan_id, pid, "Project", "full", "completed", now)
                    )
            else:
                s_row = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if not s_row:
                    conn.execute(
                        "INSERT OR IGNORE INTO scans (id, project_id, project_name, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (scan_id, pid, "Project", "full", "completed", now)
                    )
            fp = f.get("fingerprint") or compute_finding_fingerprint(pid, f)
            conn.execute("""
            INSERT OR REPLACE INTO findings (
                id, scan_id, project_id, type, title, description, remediation,
                severity, cwe_id, cve_id, language, package_name, installed_version,
                fixed_version, license, file_path, line_start, line_end, code_snippet,
                cvss_score, cvss_vector, epss_score, epss_percentile, composite_risk_score,
                quadrant, urgency, sla_days, standards, status, author_name, author_email,
                commit_hash, commit_date, commit_message, first_seen, last_seen, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                fid, scan_id, pid, f.get("type", "sast"), f.get("title", "Finding"),
                f.get("description", ""), f.get("remediation", ""), f.get("severity", "MEDIUM"),
                f.get("cwe_id"), f.get("cve_id"), f.get("language", "python"), f.get("package_name"),
                f.get("installed_version"), f.get("fixed_version"), f.get("license"),
                f.get("file_path", "app.py"), f.get("line_start", 1), f.get("line_end", 1),
                f.get("code_snippet", ""), float(f.get("cvss_score") or 7.0), f.get("cvss_vector", ""),
                float(f.get("epss_score") or 0.1), float(f.get("epss_percentile") or 0.5),
                float(f.get("composite_risk_score") or 70.0), f.get("quadrant", "ROUTINE"),
                f.get("urgency", "MEDIUM"), int(f.get("sla_days") or 90), json.dumps(f.get("standards", [])),
                f.get("status", "open"), f.get("author_name") or "Developer", f.get("author_email") or "developer@internal.net",
                f.get("commit_hash", "HEAD"), f.get("commit_date", now), f.get("commit_message", "commit"),
                f.get("first_seen", now), f.get("last_seen", now), fp
            ))
            f["id"] = fid
            return f

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
                if item.get("author_email") is None:
                    item["author_email"] = ""
                if item.get("author_name") is None:
                    item["author_name"] = "Unknown"
                enrich_finding_age(item)
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
            else:
                item["standards"] = []
            if item.get("author_email") is None:
                item["author_email"] = ""
            if item.get("author_name") is None:
                item["author_name"] = "Unknown"
            enrich_finding_age(item)
            return item

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        ticket_key: Optional[str] = None,
        platform: Optional[str] = None,
        ticket_assigned_to: Optional[str] = None,
        ticket_assigned_email: Optional[str] = None
    ) -> bool:
        with self._get_conn() as conn:
            if platform == "jira":
                conn.execute(
                    "UPDATE findings SET status = ?, jira_key = ?, ticket_assigned_to = COALESCE(?, ticket_assigned_to), ticket_assigned_email = COALESCE(?, ticket_assigned_email) WHERE id = ?",
                    (status, ticket_key, ticket_assigned_to, ticket_assigned_email, finding_id)
                )
            elif platform == "zammad":
                conn.execute(
                    "UPDATE findings SET status = ?, zammad_id = ?, ticket_assigned_to = COALESCE(?, ticket_assigned_to), ticket_assigned_email = COALESCE(?, ticket_assigned_email) WHERE id = ?",
                    (status, ticket_key, ticket_assigned_to, ticket_assigned_email, finding_id)
                )
            elif ticket_assigned_to:
                conn.execute(
                    "UPDATE findings SET status = ?, ticket_assigned_to = ?, ticket_assigned_email = ? WHERE id = ?",
                    (status, ticket_assigned_to, ticket_assigned_email, finding_id)
                )
            else:
                conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            return True

    def update_finding_confidence(self, finding_id: str, score: float, label: str, rationale: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("""
            UPDATE findings SET
                ai_confidence_score = ?,
                ai_confidence_label = ?,
                ai_confidence_rationale = ?
            WHERE id = ?
            """, (score, label, rationale, finding_id))
            return cur.rowcount > 0

    # --- Custom Rules ---
    def list_rules(self, project_id: Optional[str] = None, include_global: bool = True) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            if project_id:
                if include_global:
                    rows = conn.execute(
                        "SELECT * FROM custom_rules WHERE project_id = ? OR project_id IS NULL OR project_id = '' OR project_id = 'global' ORDER BY id ASC",
                        (project_id,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM custom_rules WHERE project_id = ? ORDER BY id ASC",
                        (project_id,)
                    ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM custom_rules ORDER BY id ASC").fetchall()

            res = []
            for r in rows:
                item = dict(r)
                item["languages"] = json.loads(item["languages"]) if item.get("languages") else []
                item["standards"] = json.loads(item["standards"]) if item.get("standards") else []
                item["is_active"] = bool(item.get("is_active"))
                res.append(item)
            return res

    def get_all_rules(self, project_id: Optional[str] = None, include_global: bool = True) -> List[Dict[str, Any]]:
        return self.list_rules(project_id=project_id, include_global=include_global)

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
            # Check if project_name needs resolution
            project_id = rule.get("project_id")
            project_name = rule.get("project_name")
            if project_id and not project_name:
                p_row = conn.execute("SELECT name FROM projects WHERE id = ?", (project_id,)).fetchone()
                if p_row:
                    project_name = p_row["name"]
                    rule["project_name"] = project_name

            conn.execute("""
            INSERT OR REPLACE INTO custom_rules (
                id, name, type, rule_category, nl_prompt, languages, severity,
                cwe, standards, regex, description, remediation, yaml_representation, is_active,
                project_id, project_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule["id"], rule["name"], rule.get("type", "sast_pattern"),
                rule.get("rule_category", "sast"), rule.get("nl_prompt", ""),
                json.dumps(rule.get("languages", [])), rule.get("severity", "MEDIUM"),
                rule.get("cwe", "CWE-699"), json.dumps(rule.get("standards", [])),
                rule.get("regex", ""), rule.get("description", ""),
                rule.get("remediation", ""), rule.get("yaml_representation", ""),
                1 if rule.get("is_active", True) else 0,
                project_id,
                project_name
            ))
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self._get_conn() as conn:
            res = conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            return res.rowcount > 0

    def create_custom_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        return self.save_rule(rule)

    def delete_custom_rule(self, rule_id: str) -> bool:
        return self.delete_rule(rule_id)

    # --- Integrations Config ---
    def get_integration(self, key: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM integrations WHERE key = ?", (key,)).fetchone()
            return json.loads(row["value"]) if row else None

    def set_integration(self, key: str, value: Dict[str, Any]):
        with self._get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO integrations (key, value) VALUES (?, ?)", (key, json.dumps(value)))


db = Database()
