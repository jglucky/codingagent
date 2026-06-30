"""Clone GitHub repositories for scanning."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


GITHUB_URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    name: str
    url: str
    default_branch: str | None = None


class GitHubCloneError(Exception):
    pass


def parse_github_url(repo_input: str) -> RepoInfo:
    """Parse a GitHub URL or owner/repo shorthand into RepoInfo."""
    repo_input = repo_input.strip().rstrip("/")

    if "/" in repo_input and "github.com" not in repo_input and not repo_input.startswith("http"):
        parts = repo_input.split("/", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            owner, name = parts
            name = name.removesuffix(".git")
            return RepoInfo(
                owner=owner,
                name=name,
                url=f"https://github.com/{owner}/{name}.git",
            )

    if repo_input.startswith("git@"):
        match = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$", repo_input)
        if match:
            owner = match.group("owner")
            name = match.group("repo")
            return RepoInfo(
                owner=owner,
                name=name,
                url=f"https://github.com/{owner}/{name}.git",
            )

    if not repo_input.startswith("http"):
        repo_input = f"https://github.com/{repo_input}"

    parsed = urlparse(repo_input)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise GitHubCloneError(f"Not a GitHub repository URL: {repo_input}")

    match = GITHUB_URL_PATTERN.match(repo_input)
    if not match:
        raise GitHubCloneError(f"Could not parse GitHub repository: {repo_input}")

    owner = match.group("owner")
    name = match.group("repo").removesuffix(".git")
    return RepoInfo(owner=owner, name=name, url=f"https://github.com/{owner}/{name}.git")


def _authenticated_clone_url(url: str, token: str | None) -> str:
    if not token:
        return url
    return url.replace("https://", f"https://{token}@")


def clone_repository(
    repo_input: str,
    destination: Path,
    *,
    branch: str | None = None,
    depth: int | None = 1,
    github_token: str | None = None,
) -> tuple[RepoInfo, Path]:
    """Clone a GitHub repository into destination and return repo info + local path."""
    repo = parse_github_url(repo_input)
    token = github_token or os.environ.get("GITHUB_TOKEN")
    clone_url = _authenticated_clone_url(repo.url, token)

    if destination.exists():
        raise GitHubCloneError(f"Destination already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["git", "clone", "--quiet"]
    if depth:
        cmd.extend(["--depth", str(depth)])
    if branch:
        cmd.extend(["--branch", branch, "--single-branch"])
    cmd.extend([clone_url, str(destination)])

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise GitHubCloneError("Git is not installed or not on PATH.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or exc.stdout or "").strip()
        hint = ""
        if "Authentication failed" in stderr or "could not read Username" in stderr:
            hint = " Set GITHUB_TOKEN for private repositories."
        elif "Remote branch" in stderr and "not found" in stderr:
            hint = f" Branch '{branch}' was not found."
        raise GitHubCloneError(f"Failed to clone {repo.url}: {stderr}{hint}") from exc

    return repo, destination