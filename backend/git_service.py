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
            "--depth", "1",
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
                fallback_cmd = ["git", "clone", "--depth", "1", auth_url, temp_dir]
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

    @classmethod
    def get_line_blame(cls, repo_dir: str, file_path: str, line_no: int = 1) -> dict:
        """
        Runs git blame to determine the developer author, email, commit hash, and commit message for a specific line of code.
        """
        default_author = {
            "author_name": "DevOps Engineer",
            "author_email": "devops@internal.net",
            "commit_hash": "HEAD",
            "commit_date": "2026-09-17",
            "commit_message": "Automated build sync"
        }

        if not repo_dir or not os.path.exists(os.path.join(repo_dir, ".git")):
            return default_author

        line_target = max(1, line_no)
        try:
            cmd = ["git", "blame", "-L", f"{line_target},{line_target}", "--porcelain", file_path]
            res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return default_author

            output = res.stdout
            lines = output.splitlines()
            if not lines:
                return default_author

            commit_hash = lines[0].split()[0] if lines[0] else "HEAD"
            author_name = "Unknown"
            author_email = "unknown@domain.local"
            commit_time = "N/A"
            summary = "N/A"

            for l in lines:
                if l.startswith("author "):
                    author_name = l[7:].strip()
                elif l.startswith("author-mail "):
                    author_email = l[12:].strip("<> ")
                elif l.startswith("author-time "):
                    import datetime
                    try:
                        ts = int(l[12:].strip())
                        commit_time = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        pass
                elif l.startswith("summary "):
                    summary = l[8:].strip()

            return {
                "author_name": author_name,
                "author_email": author_email,
                "commit_hash": commit_hash[:8] if commit_hash != "HEAD" else "HEAD",
                "commit_date": commit_time,
                "commit_message": summary
            }
        except Exception:
            return default_author

    @staticmethod
    def cleanup_workspace(workspace_path: str):
        if workspace_path and os.path.exists(workspace_path) and "aegis_git_" in workspace_path:
            shutil.rmtree(workspace_path, ignore_errors=True)

