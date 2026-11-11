"""
AegisSec - Git Repository & PAT Authentication Service
Handles authenticated repository cloning, branch selection, token masking, and workspace lifecycle.
"""

import os
import re
import shutil
import tempfile
import subprocess
from typing import Tuple, Optional


class GitService:
    @staticmethod
    def mask_token(text: str, token: Optional[str]) -> str:
        """
        Ensures PAT credentials never leak into stdout, stderr, or error messages.
        """
        if not token:
            return text
        return text.replace(token, "******")

    @classmethod
    def clone_repository(
        cls,
        git_url: str,
        git_branch: str = "main",
        git_pat: Optional[str] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Clones a remote git repository into an isolated temporary workspace.
        Returns: (success: bool, workspace_path_or_error: str, commit_hash: Optional[str])
        """
        if not git_url:
            return False, "Git repository URL is required.", None

        # Check if local path is passed for testing
        if os.path.exists(git_url) and os.path.isdir(git_url):
            return True, git_url, "local-head"

        # Construct authenticated URL
        auth_url = git_url.strip()
        if git_pat and git_pat.strip():
            pat = git_pat.strip()
            if auth_url.startswith("https://"):
                # Handle GitHub, GitLab, Bitbucket PAT injection
                if "gitlab.com" in auth_url:
                    auth_url = auth_url.replace("https://", f"https://oauth2:{pat}@")
                elif "bitbucket.org" in auth_url:
                    auth_url = auth_url.replace("https://", f"https://x-token-auth:{pat}@")
                else:
                    # Default GitHub / generic HTTPS
                    auth_url = auth_url.replace("https://", f"https://{pat}@")

        temp_dir = tempfile.mkdtemp(prefix="aegis_git_")

        clone_cmd = [
            "git", "clone",
            "--single-branch",
            "-b", git_branch,
            auth_url,
            temp_dir
        ]

        try:
            res = subprocess.run(
                clone_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120
            )

            if res.returncode != 0:
                # If branch failed, try default clone without -b
                fallback_cmd = ["git", "clone", auth_url, temp_dir]
                fb_res = subprocess.run(fallback_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
                if fb_res.returncode != 0:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    safe_err = cls.mask_token(fb_res.stderr, git_pat)
                    return False, f"Git clone failed: {safe_err}", None

            # Get latest commit hash
            commit_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            commit_hash = commit_res.stdout.strip() if commit_res.returncode == 0 else "HEAD"

            return True, temp_dir, commit_hash

        except subprocess.TimeoutExpired:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False, "Git clone timed out after 120 seconds.", None
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            safe_err = cls.mask_token(str(e), git_pat)
            return False, f"Git operation encountered an unexpected error: {safe_err}", None

    # Identifiers for automated bots or platform triage staff to exclude in favor of true code committers
    APPSEC_PLATFORM_IDENTIFIERS = {
        "devops engineer", "devops@internal.net", "pipeline-bot@supplychain.net",
        "aegissec admin", "admin@aegissec.internal", "admin@sentinel.internal",
        "security-bot", "sentinel-bot", "appsec-bot", "appsec", "github-actions[bot]",
        "automated build sync", "devops", "platform admin", "appsec admin"
    }

    @classmethod
    def get_repo_committer(cls, repo_dir: str = ".") -> dict:
        """
        Extracts the human developer committer from the Git repository history or configuration,
        strictly avoiding AppSec platform administrators or automated bot handles.
        """
        import datetime
        fallback = {
            "author_name": "Developer",
            "author_email": "",
            "commit_hash": "HEAD",
            "commit_date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "commit_message": "Repository commit"
        }

        # Ensure safe.directory is configured so git never errors with dubious ownership
        try:
            subprocess.run(["git", "config", "--global", "--add", "safe.directory", "*"], capture_output=True, timeout=2)
        except Exception:
            pass

        # Build candidate search directories to locate the true Git repository root
        candidates = []
        if repo_dir and os.path.exists(repo_dir):
            candidates.append(repo_dir)
        for cand in [os.getcwd(), "/app", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]:
            if cand and os.path.exists(cand) and cand not in candidates:
                candidates.append(cand)

        for cwd_target in candidates:
            try:
                root_res = subprocess.run(
                    ["git", "rev-parse", "--show-toplevel"],
                    cwd=cwd_target, capture_output=True, text=True, timeout=3
                )
                target_root = root_res.stdout.strip() if root_res.returncode == 0 and root_res.stdout.strip() else cwd_target

                res = subprocess.run(
                    ["git", "log", "-n", "30", "--format=%an\t%ae\t%h\t%ad\t%s", "--date=short"],
                    cwd=target_root, capture_output=True, text=True, timeout=5
                )
                if res.returncode == 0 and res.stdout.strip():
                    for line in res.stdout.splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            an, ae = parts[0].strip(), parts[1].strip()
                            is_platform = any(ident in an.lower() or ident in ae.lower() for ident in cls.APPSEC_PLATFORM_IDENTIFIERS)
                            is_generic = an.lower() in ("developer", "unknown", "")
                            if not is_platform and not is_generic and ae:
                                return {
                                    "author_name": an,
                                    "author_email": ae,
                                    "commit_hash": parts[2] if len(parts) > 2 else "HEAD",
                                    "commit_date": parts[3] if len(parts) > 3 else "",
                                    "commit_message": parts[4] if len(parts) > 4 else "Repository commit"
                                }

                # Fallback to local git config if no clean commit history found in this target
                cfg_name = subprocess.run(["git", "config", "user.name"], cwd=target_root, capture_output=True, text=True).stdout.strip()
                cfg_mail = subprocess.run(["git", "config", "user.email"], cwd=target_root, capture_output=True, text=True).stdout.strip()
                if cfg_name or cfg_mail:
                    is_platform_cfg = any(ident in cfg_name.lower() or ident in cfg_mail.lower() for ident in cls.APPSEC_PLATFORM_IDENTIFIERS)
                    if not is_platform_cfg and cfg_name.lower() not in ("developer", "unknown", ""):
                        return {
                            "author_name": cfg_name or "Developer",
                            "author_email": cfg_mail or "",
                            "commit_hash": "HEAD",
                            "commit_date": datetime.datetime.now().strftime("%Y-%m-%d"),
                            "commit_message": "Local repository workspace"
                        }
            except Exception:
                continue

        return fallback

    @classmethod
    def get_line_blame(cls, repo_dir: str, file_path: str, line_no: int = 1) -> dict:
        """
        Runs git blame to determine the developer author, email, commit hash, and commit message
        for a specific line of code. Fetches the actual committer who introduced the code,
        skipping AppSec triage administrators or automated platform defaults.
        """
        import datetime

        # Ensure safe.directory is configured
        try:
            subprocess.run(["git", "config", "--global", "--add", "safe.directory", "*"], capture_output=True, timeout=2)
        except Exception:
            pass

        # If file_path is a URL or dynamic endpoint (e.g. DAST findings), attribute directly to repo committer
        clean_path = str(file_path or "").strip()
        if not clean_path or clean_path.startswith(("http://", "https://", "ws://", "wss://")) or "://" in clean_path:
            return cls.get_repo_committer(repo_dir or ".")

        if not repo_dir or not os.path.exists(repo_dir):
            return cls.get_repo_committer(os.getcwd())

        # 1. Resolve actual Git root directory
        git_root = repo_dir
        try:
            chk = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=repo_dir, capture_output=True, text=True, timeout=3
            )
            if chk.returncode == 0 and chk.stdout.strip():
                git_root = chk.stdout.strip()
        except Exception:
            pass

        # 2. Compute path relative to git root
        try:
            if os.path.isabs(clean_path):
                rel_file = os.path.relpath(clean_path, git_root)
            else:
                rel_file = os.path.relpath(os.path.join(repo_dir, clean_path), git_root)
            rel_file = rel_file.replace("\\", "/")
        except Exception:
            rel_file = clean_path

        # 3. Clamp line number to valid lines in file to prevent git blame out-of-bounds error
        full_file_path = os.path.join(git_root, rel_file)
        total_lines = 1
        if os.path.exists(full_file_path) and os.path.isfile(full_file_path):
            try:
                with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_lines = max(1, sum(1 for _ in f))
            except Exception:
                pass
        line_target = max(1, min(line_no, total_lines))

        # 4. Execute git blame with whitespace tolerance
        author_name = None
        author_email = None
        commit_hash = "HEAD"
        commit_time = "N/A"
        summary = "N/A"

        try:
            cmd = ["git", "blame", "-L", f"{line_target},{line_target}", "-w", "--porcelain", "--", rel_file]
            res = subprocess.run(cmd, cwd=git_root, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.splitlines()
                if lines:
                    commit_hash = lines[0].split()[0] if lines[0] else "HEAD"
                    for l in lines:
                        if l.startswith("author "):
                            author_name = l[7:].strip()
                        elif l.startswith("author-mail "):
                            author_email = l[12:].strip("<> ")
                        elif l.startswith("author-time "):
                            try:
                                ts = int(l[12:].strip())
                                commit_time = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                            except Exception:
                                pass
                        elif l.startswith("summary "):
                            summary = l[8:].strip()
        except Exception:
            pass

        # 5. Check if blame author is an AppSec platform default / bot or missing
        is_appsec_author = False
        if author_name or author_email:
            check_str = f"{author_name or ''} {author_email or ''}".lower()
            is_appsec_author = any(ident in check_str for ident in cls.APPSEC_PLATFORM_IDENTIFIERS)
            if (author_name or "").lower() in ("developer", "unknown"):
                is_appsec_author = True

        if not author_name or not author_email or is_appsec_author or commit_hash == "0000000000000000000000000000000000000000":
            # Walk git log history for this specific file to locate the real code committer
            try:
                log_cmd = [
                    "git", "log", "-n", "15",
                    "--format=%an\t%ae\t%h\t%ad\t%s",
                    "--date=short", "--", rel_file
                ]
                log_res = subprocess.run(log_cmd, cwd=git_root, capture_output=True, text=True, timeout=5)
                if log_res.returncode == 0 and log_res.stdout.strip():
                    for entry in log_res.stdout.splitlines():
                        parts = entry.split("\t")
                        if len(parts) >= 2:
                            l_name, l_email = parts[0].strip(), parts[1].strip()
                            if not any(ident in l_name.lower() or ident in l_email.lower() for ident in cls.APPSEC_PLATFORM_IDENTIFIERS) and l_name.lower() not in ("developer", "unknown"):
                                return {
                                    "author_name": l_name,
                                    "author_email": l_email,
                                    "commit_hash": parts[2] if len(parts) > 2 else commit_hash[:8],
                                    "commit_date": parts[3] if len(parts) > 3 else commit_time,
                                    "commit_message": parts[4] if len(parts) > 4 else summary
                                }
            except Exception:
                pass

        if not author_name or is_appsec_author:
            # Fallback to repo committer
            return cls.get_repo_committer(git_root)

        return {
            "author_name": author_name,
            "author_email": author_email or "",
            "commit_hash": commit_hash[:8] if commit_hash != "HEAD" else "HEAD",
            "commit_date": commit_time,
            "commit_message": summary
        }

    @staticmethod
    def cleanup_workspace(workspace_path: str):
        if workspace_path and os.path.exists(workspace_path) and "aegis_git_" in workspace_path:
            shutil.rmtree(workspace_path, ignore_errors=True)

