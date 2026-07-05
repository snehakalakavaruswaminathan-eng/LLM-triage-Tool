"""Create draft GitHub pull requests from patch suggestion files."""

from __future__ import annotations

import re
from pathlib import Path

from config import get_settings


def create_draft_prs_from_patches(patch_files: list[str]) -> list[str]:
    """
    Create draft PRs via GitHub API when credentials are configured.
    Returns list of PR URLs. Falls back to logging instructions when unconfigured.
    """
    settings = get_settings()
    if not settings.github_token or not settings.github_repo:
        return [
            "GitHub PR creation skipped: set GITHUB_TOKEN and GITHUB_REPO to enable draft PRs."
        ]

    try:
        from github import Github
    except ImportError:
        return ["PyGithub not installed — cannot create draft PRs."]

    github = Github(settings.github_token)
    repo = github.get_repo(settings.github_repo)
    urls: list[str] = []

    for index, patch_path in enumerate(patch_files, start=1):
        path = Path(patch_path)
        if not path.exists():
            continue

        content = path.read_text(encoding="utf-8")
        title = _extract_title(content) or f"AI draft fix #{index}"
        safe_base = re.sub(r"[^a-zA-Z0-9_-]", "-", settings.github_base_branch)
        branch_name = f"ai-fix/draft-{index}-{safe_base}"

        base = repo.get_branch(settings.github_base_branch)
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)

        # Commit the patch suggestion file itself for human review.
        repo.create_file(
            path=f"ai-patches/{path.name}",
            message=title,
            content=content,
            branch=branch_name,
        )

        pr = repo.create_pull(
            title=title,
            body=_build_pr_body(content),
            head=branch_name,
            base=settings.github_base_branch,
            draft=True,
        )
        urls.append(pr.html_url)

    return urls


def _extract_title(content: str) -> str | None:
    match = re.search(r"^#\s+Draft Patch Suggestion\s+(.+)$", content, re.MULTILINE)
    if match:
        return match.group(1).strip()[:120]
    return None


def _build_pr_body(content: str) -> str:
    return (
        "## AI-generated draft remediation\n\n"
        "This pull request was created automatically from scanner triage output.\n"
        "**A human must review, validate, and adapt these changes before merge.**\n\n"
        "---\n\n"
        f"{content[:6000]}"
    )
