"""Tests for configuration loading and environment overrides."""

from pathlib import Path

from reconcopilot.config import DEFAULT_CONFIG, load_config


def test_default_config_fallback() -> None:
    cfg = load_config(config_path=Path("/nonexistent/path/config.yaml"))
    assert cfg.app.name == "ReconCopilot"
    assert cfg.ai.provider == "anthropic"
    assert cfg.ai.model == "claude-sonnet-4-6"
    assert cfg.scope.strict_mode is True


def test_anthropic_api_key_env_override(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-secret-key-12345")
    cfg = load_config(config_path=Path("/nonexistent/path/config.yaml"))
    assert cfg.ai.api_key == "sk-ant-test-secret-key-12345"


def test_database_path_env_override(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_PATH", "/tmp/custom_recon.db")
    cfg = load_config(config_path=Path("/nonexistent/path/config.yaml"))
    assert cfg.database.path == "/tmp/custom_recon.db"


def test_generic_env_override(monkeypatch) -> None:
    monkeypatch.setenv("RECONCOPILOT_AI_MAX_TOKENS", "8192")
    monkeypatch.setenv("RECONCOPILOT_APP_LOG_LEVEL", "DEBUG")
    cfg = load_config(config_path=Path("/nonexistent/path/config.yaml"))
    assert cfg.ai.max_tokens == 8192
    assert cfg.app.log_level == "DEBUG"


def test_yaml_config_file_loading(tmp_path) -> None:
    config_file = tmp_path / "custom_config.yaml"
    config_file.write_text(
        "app:\n  environment: production\nai:\n  model: custom-claude-model\n"
    )

    cfg = load_config(config_path=config_file)
    assert cfg.app.environment == "production"
    assert cfg.ai.model == "custom-claude-model"
    # Preserves other defaults
    assert cfg.app.name == DEFAULT_CONFIG["app"]["name"]
