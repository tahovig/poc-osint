import json

import pytest

from poc_osint.cli import main
from poc_osint.crtsh import CrtShError
from poc_osint.headers import HeaderFindings
from poc_osint.recon import SubdomainReport

SAMPLE_REPORTS = [
    SubdomainReport(
        host="www.example.com",
        port=80,
        scheme="http",
        is_live=True,
        status_code=200,
        error=None,
        findings=HeaderFindings(
            missing_security_headers=["Content-Security-Policy"],
            server_banner="nginx",
            powered_by=None,
            fingerprint_matches=["nginx"],
        ),
    ),
    SubdomainReport(
        host="dead.example.com",
        port=443,
        scheme="https",
        is_live=False,
        status_code=None,
        error="connection refused",
        findings=None,
    ),
]


def test_lookup_invalid_domain_exits_nonzero(capsys):
    exit_code = main(["lookup", "not a domain"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not a valid domain" in captured.err


def test_missing_command_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code != 0


def test_lookup_prints_table_by_default(monkeypatch, capsys):
    async def fake_run_recon(domain, **kwargs):
        return SAMPLE_REPORTS

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)

    exit_code = main(["lookup", "example.com"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "www.example.com" in captured.out
    assert "dead.example.com" in captured.out


def test_lookup_json_flag_outputs_valid_json(monkeypatch, capsys):
    async def fake_run_recon(domain, **kwargs):
        return SAMPLE_REPORTS

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)

    exit_code = main(["lookup", "example.com", "--json"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert exit_code == 0
    assert len(parsed) == 2
    assert parsed[0]["host"] == "www.example.com"


def test_lookup_crtsh_error_exits_nonzero(monkeypatch, capsys):
    async def fake_run_recon(domain, **kwargs):
        raise CrtShError("crt.sh query failed for 'example.com' after 3 attempts")

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)

    exit_code = main(["lookup", "example.com"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "crt.sh" in captured.err


def test_lookup_passes_through_max_concurrency_and_delay(monkeypatch):
    captured_kwargs = {}

    async def fake_run_recon(domain, **kwargs):
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)

    main(["lookup", "example.com", "--max-concurrency", "5", "--delay", "0.5"])

    assert captured_kwargs == {"max_concurrency": 5, "delay": 0.5}


def test_lookup_save_writes_json_file(monkeypatch, tmp_path):
    async def fake_run_recon(domain, **kwargs):
        return SAMPLE_REPORTS

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)
    save_path = tmp_path / "result.json"

    exit_code = main(["lookup", "example.com", "--save", str(save_path)])

    assert exit_code == 0
    saved = json.loads(save_path.read_text())
    assert len(saved) == 2
    assert saved[0]["host"] == "www.example.com"


def test_lookup_save_failure_exits_nonzero(monkeypatch, capsys, tmp_path):
    async def fake_run_recon(domain, **kwargs):
        return SAMPLE_REPORTS

    monkeypatch.setattr("poc_osint.cli.run_recon", fake_run_recon)
    unwritable_path = tmp_path / "no-such-dir" / "result.json"

    exit_code = main(["lookup", "example.com", "--save", str(unwritable_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "could not save" in captured.err


def test_compare_prints_text_diff_by_default(tmp_path, capsys):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps([{"host": "gone.example.com", "port": 80}]))
    new_path.write_text(json.dumps([{"host": "new.example.com", "port": 80}]))

    exit_code = main(["compare", str(old_path), str(new_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "+ ADDED    new.example.com:80" in captured.out
    assert "- REMOVED  gone.example.com:80" in captured.out


def test_compare_json_flag_outputs_valid_json(tmp_path, capsys):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps([]))
    new_path.write_text(json.dumps([{"host": "new.example.com", "port": 80}]))

    exit_code = main(["compare", str(old_path), str(new_path), "--json"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert exit_code == 0
    assert parsed["added"] == [{"host": "new.example.com", "port": 80}]


def test_compare_missing_file_exits_nonzero(tmp_path, capsys):
    exit_code = main(["compare", str(tmp_path / "missing.json"), str(tmp_path / "also-missing.json")])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.err
