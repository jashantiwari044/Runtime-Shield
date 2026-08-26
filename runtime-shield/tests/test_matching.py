"""Glob and tool-name matching.

These are regression tests: the previous engine's glob translation required a
leading directory, so `**/.ssh/**` silently failed to match `.ssh/id_rsa` and
the rule protecting SSH keys never fired.
"""

import pytest

from shield.matching import arguments_match, glob_match, normalize_path, tool_match, value_match


@pytest.mark.parametrize("path,pattern", [
    (".ssh/id_rsa", "**/.ssh/**"),
    ("/home/user/.ssh/id_rsa", "**/.ssh/**"),
    ("/home/user/.ssh", "**/.ssh/**"),
    ("a/b/c/.aws/credentials", "**/.aws/**"),
    ("key.pem", "**/*.pem"),
    ("/deep/nested/key.pem", "**/*.pem"),
    (".env", "**/.env"),
    ("app/.env", "**/.env"),
    ("/etc/shadow", "/etc/shadow"),
    ("id_rsa.pub", "**/id_rsa*"),
    ("C:\\Users\\me\\.ssh\\id_rsa", "**/.ssh/**"),
])
def test_glob_matches(path, pattern):
    assert glob_match(path, pattern), f"{path!r} should match {pattern!r}"


@pytest.mark.parametrize("path,pattern", [
    ("notes.txt", "**/.ssh/**"),
    ("ssh/config", "**/.ssh/**"),
    ("app.env", "**/.env"),
    ("/etc/hosts", "/etc/shadow"),
    ("readme.md", "**/*.pem"),
    ("my.pem.backup.txt", "**/*.pem"),
])
def test_glob_does_not_match(path, pattern):
    assert not glob_match(path, pattern), f"{path!r} should NOT match {pattern!r}"


def test_single_star_does_not_cross_separator():
    assert glob_match("src/main.py", "src/*.py")
    assert not glob_match("src/deep/main.py", "src/*.py")
    assert glob_match("src/deep/main.py", "src/**/*.py")


def test_normalize_path():
    assert normalize_path("a\\b\\c") == "a/b/c"
    assert normalize_path("a//b///c") == "a/b/c"
    assert normalize_path("/tmp/") == "/tmp"
    assert normalize_path("/") == "/"


@pytest.mark.parametrize("tool,pattern,expected", [
    ("exec", "shell_exec|run_command|exec", True),
    ("exec", "shell_exec|run_command", False),
    ("read_file", "read_*", True),
    ("anything", "*", True),
    ("ReadFile", "readfile", True),          # matching is case-insensitive
    ("write_file", "read_*", False),
    ("run_shell", "re:^run_", True),
    ("shell_run", "re:^run_", False),
])
def test_tool_match(tool, pattern, expected):
    assert tool_match(tool, pattern) is expected


def test_tool_match_bad_regex_is_not_fatal():
    assert tool_match("exec", "re:[unclosed") is False


def test_value_match_forms():
    assert value_match("/tmp/x", "/tmp/*")
    assert value_match("hello world", {"contains": "WORLD"})
    assert value_match("abc123", {"regex": r"^\w+\d+$"})
    assert value_match(42, {"equals": 42})
    assert value_match("b", {"any_of": ["a", "b"]})
    assert not value_match("c", {"any_of": ["a", "b"]})


def test_arguments_match_requires_every_key():
    args = {"path": "/tmp/x", "mode": "w"}
    assert arguments_match(args, {"path": "/tmp/*"})
    assert arguments_match(args, {"path": "/tmp/*", "mode": "w"})
    assert not arguments_match(args, {"path": "/tmp/*", "missing": "x"})
    assert arguments_match(args, {}) is True
