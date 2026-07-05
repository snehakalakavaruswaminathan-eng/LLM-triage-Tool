"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI Security Triage Service"
    app_version: str = "1.0.0"
    debug: bool = False

    # Paths
    base_dir: Path = Path(__file__).resolve().parent
    reports_dir: Path = base_dir / "reports"
    prompts_dir: Path = base_dir / "prompts"
    patches_dir: Path = base_dir / "patches"

    # LLM
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_mock_mode: bool = False
    llm_temperature: float = 0.2
    llm_max_tokens: int = 2048

    # Triage
    top_n_findings: int = 3
    max_code_snippet_lines: int = 10
    cluster_similarity_threshold: float = 0.85

    # GitHub PR (optional)
    github_token: str = ""
    github_repo: str = ""
    github_base_branch: str = "main"


@lru_cache
def get_settings() -> Settings:
    return Settings()
