from __future__ import annotations

import io
import json
from pathlib import Path

from xss_checker.cli import EXIT_CLEAN, EXIT_DETECTED, EXIT_ERROR, main


def run(*argv: str, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_clean_input_exits_zero() -> None:
    code, out, _ = run("hello world")
    assert code == EXIT_CLEAN
    assert "clean" in out


def test_malicious_input_exits_one() -> None:
    code, out, _ = run("<script>alert(1)</script>")
    assert code == EXIT_DETECTED
    assert "script-tag" in out


def test_json_output_for_single_value() -> None:
    code, out, _ = run("--json", "<script>alert(1)</script>")
    payload = json.loads(out)
    assert code == EXIT_DETECTED
    assert payload["severity"] == "critical"


def test_json_output_for_multiple_values_is_a_list() -> None:
    code, out, _ = run("--json", "safe", "<script>x</script>")
    payload = json.loads(out)
    assert code == EXIT_DETECTED
    assert isinstance(payload, list)
    assert [item["malicious"] for item in payload] == [False, True]


def test_quiet_mode_suppresses_output() -> None:
    code, out, _ = run("--quiet", "<script>x</script>")
    assert code == EXIT_DETECTED
    assert out == ""


def test_min_severity_filter() -> None:
    assert run("--min-severity", "high", "width:expression(alert(1))")[0] == EXIT_CLEAN
    assert run("width:expression(alert(1))")[0] == EXIT_DETECTED


def test_does_not_flag_legitimate_html() -> None:
    assert run("<b>bold</b>")[0] == EXIT_CLEAN
    assert run('<a href="https://example.com">link</a>')[0] == EXIT_CLEAN
    assert run('<img src="cat.jpg" alt="a cat">')[0] == EXIT_CLEAN


def test_reads_from_stdin_when_not_a_tty() -> None:
    code, out, _ = run(stdin="safe line\n<script>x</script>\n")
    assert code == EXIT_DETECTED
    assert out.count("\n") >= 2


def test_reads_from_file(tmp_path: Path) -> None:
    target = tmp_path / "payloads.txt"
    target.write_text("hello\n<img src=x onerror=alert(1)>\n", encoding="utf-8")
    code, out, _ = run("--file", str(target))
    assert code == EXIT_DETECTED
    assert "event-handler" in out


def test_missing_file_reports_error() -> None:
    code, _, err = run("--file", "/nonexistent/payloads.txt")
    assert code == EXIT_ERROR
    assert "error:" in err


def test_empty_stdin_reports_error() -> None:
    code, _, err = run(stdin="")
    assert code == EXIT_ERROR
    assert "no input" in err


def test_list_patterns() -> None:
    code, out, _ = run("--list-patterns")
    assert code == EXIT_CLEAN
    assert "script-tag" in out


def test_no_decode_flag_skips_decoded_layers() -> None:
    _, raw_only, _ = run("--json", "--no-decode", "%3Cscript%3Ealert(1)%3C/script%3E")
    _, decoded, _ = run("--json", "%3Cscript%3Ealert(1)%3C/script%3E")
    assert json.loads(raw_only)["severity"] == "medium"
    assert json.loads(decoded)["severity"] == "critical"


def test_text_output_includes_fix_guidance() -> None:
    code, out, _ = run("<script>alert(1)</script>")
    assert code == EXIT_DETECTED
    assert "fix:" in out
    assert "sanitizer" in out.lower()


def test_fix_guidance_not_repeated_for_duplicate_pattern_matches() -> None:
    code, out, _ = run("<script>x</script><script>y</script>")
    assert code == EXIT_DETECTED
    assert out.count("fix:") == 1


def test_json_output_includes_remediation() -> None:
    _, out, _ = run("--json", "<script>alert(1)</script>")
    payload = json.loads(out)
    assert payload["findings"][0]["remediation"]


def test_list_patterns_includes_fix_guidance() -> None:
    code, out, _ = run("--list-patterns")
    assert code == EXIT_CLEAN
    assert "fix:" in out
