"""Unit tests for scripts/lib/test_logger.py."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

# Ensure scripts/ is importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging


@pytest.fixture(autouse=True)
def _isolate_loggers():
    """Remove loggers created during each test to prevent handler leaks."""
    created: list[str] = []
    orig = logging.getLogger

    def tracking_get(name=None):
        logger = orig(name)
        if name:
            created.append(name)
        return logger

    logging.getLogger = tracking_get
    yield
    logging.getLogger = orig
    manager = logging.Logger.manager
    for name in created:
        if name in manager.loggerDict:
            logger = manager.loggerDict[name]
            if isinstance(logger, logging.Logger):
                logger.handlers.clear()
            del manager.loggerDict[name]


class TestConfigureTestLogging:
    """Core configure_test_logging behaviour."""

    def test_returns_logger_with_correct_name(self):
        log = configure_test_logging("test_returns_name")
        assert log.name == "test_returns_name"

    def test_sets_level_to_debug_by_default(self):
        log = configure_test_logging("test_level_debug")
        assert log.level == logging.DEBUG

    def test_custom_level(self):
        log = configure_test_logging("test_custom_level", level=logging.WARNING)
        assert log.level == logging.WARNING

    def test_human_mode_formatter(self):
        log = configure_test_logging("test_human_fmt", json_mode=False)
        stderr_handler = log.handlers[0]
        assert "%(levelname)" in stderr_handler.formatter._fmt or \
               hasattr(stderr_handler.formatter, 'format')

    def test_json_mode_formatter(self, capsys):
        log = configure_test_logging("test_json_fmt", json_mode=True)
        log.info("hello", extra={"x": 1})
        captured = capsys.readouterr()
        # JSON output goes to stderr
        line = captured.err.strip().split("\n")[-1]
        parsed = json.loads(line)
        assert parsed["msg"] == "hello"
        assert parsed["x"] == 1
        assert parsed["level"] == "INFO"

    def test_idempotent_handler_count(self):
        log1 = configure_test_logging("test_idempotent")
        count = len(log1.handlers)
        log2 = configure_test_logging("test_idempotent")
        assert log2 is log1
        assert len(log2.handlers) == count

    def test_no_propagation(self):
        log = configure_test_logging("test_no_prop")
        assert log.propagate is False

    def test_has_stderr_handler(self):
        log = configure_test_logging("test_stderr_h")
        stream_handlers = [
            h for h in log.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) >= 1

    def test_creates_log_directory(self, tmp_path, monkeypatch):
        # Patch _LOG_DIR to tmp_path to avoid side effects.
        import scripts.lib.test_logger as mod
        monkeypatch.setattr(mod, "_LOG_DIR", tmp_path / "logs" / "verification")
        log = configure_test_logging("test_logdir_create")
        file_handlers = [h for h in log.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1
        assert (tmp_path / "logs" / "verification").is_dir()

    def test_json_timestamp_is_iso(self, capsys):
        log = configure_test_logging("test_json_ts", json_mode=True)
        log.info("ts check")
        line = capsys.readouterr().err.strip().split("\n")[-1]
        parsed = json.loads(line)
        assert "T" in parsed["ts"]  # ISO-8601 has 'T' separator

    def test_json_extras_passed_through(self, capsys):
        log = configure_test_logging("test_extras", json_mode=True)
        log.warning("extra test", extra={"bead_id": "bd-42", "checks": 7})
        line = capsys.readouterr().err.strip().split("\n")[-1]
        parsed = json.loads(line)
        assert parsed["bead_id"] == "bd-42"
        assert parsed["checks"] == 7

    def test_autodetect_json_from_argv(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["script", "--json"])
        log = configure_test_logging("test_autodetect")
        # When --json in argv and json_mode=None, should pick JSON formatter
        from scripts.lib.test_logger import _JsonFormatter
        assert any(isinstance(h.formatter, _JsonFormatter) for h in log.handlers)

    def test_human_mode_when_no_json_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["script"])
        log = configure_test_logging("test_no_json_flag")
        from scripts.lib.test_logger import _HumanFormatter
        stderr_handlers = [
            h for h in log.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert any(isinstance(h.formatter, _HumanFormatter) for h in stderr_handlers)


class TestSelfTest:
    """The built-in self_test() must complete without error."""

    def test_self_test_runs(self, capsys):
        from scripts.lib.test_logger import self_test
        self_test()
        assert "PASSED" in capsys.readouterr().out
