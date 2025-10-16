import pytest

from reconscript import cli


def test_help_output_includes_link(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(["--help"])

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Full guide available in HELP.md" in captured.out
