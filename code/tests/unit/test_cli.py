import pytest

from poc_osint.cli import main


def test_lookup_valid_domain_exits_zero(capsys):
    exit_code = main(["lookup", "example.com"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "example.com" in captured.out


def test_lookup_invalid_domain_exits_nonzero(capsys):
    exit_code = main(["lookup", "not a domain"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not a valid domain" in captured.err


def test_missing_command_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code != 0
