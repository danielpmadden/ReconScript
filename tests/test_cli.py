# Modified by codex: 2024-05-08

from unittest import mock

from reconscript import cli
from reconscript.scanner import probe_http_service
from requests import Response
from requests.structures import CaseInsensitiveDict


def test_parse_args_includes_dry_run_flag():
    args = cli.parse_args(["--target", "127.0.0.1", "--dry-run"])

    assert args.dry_run is True


def test_main_passes_dry_run_and_outfile(tmp_path):
    outfile = tmp_path / "reports" / "scan.json"
    report = {"ports": [80], "open_ports": [], "findings": []}
    with (
        mock.patch("reconscript.cli.run_recon", return_value=report) as mock_run,
        mock.patch("reconscript.cli.write_report") as mock_writer,
        mock.patch("reconscript.cli.Console") as mock_console,
    ):
        mock_writer.return_value = (outfile, "json")
        console_instance = mock.Mock()
        console_instance.print = mock.Mock()
        mock_console.return_value = console_instance
        exit_code = cli.main(
            [
                "--target",
                "127.0.0.1",
                "--dry-run",
                "--outfile",
                str(outfile),
            ]
        )

    assert exit_code == 0
    run_args = mock_run.call_args.kwargs
    assert run_args["dry_run"] is True
    mock_writer.assert_called_once_with(report, outfile, "json")


def test_main_respects_format_flag(tmp_path):
    outfile = tmp_path / "reports" / "scan.out"
    report = {"ports": [80], "open_ports": [80], "findings": []}
    with (
        mock.patch("reconscript.cli.run_recon", return_value=report),
        mock.patch("reconscript.cli.write_report") as mock_writer,
        mock.patch("reconscript.cli.Console") as mock_console,
    ):
        mock_writer.return_value = (outfile, "html")
        console_instance = mock.Mock()
        console_instance.print = mock.Mock()
        mock_console.return_value = console_instance
        cli.main(
            [
                "--target",
                "127.0.0.1",
                "--outfile",
                str(outfile),
                "--format",
                "html",
            ]
        )

    mock_writer.assert_called_once_with(report, outfile, "html")


def test_main_defaults_to_html_and_opens_browser(tmp_path):
    report = {
        "ports": [80],
        "open_ports": [80],
        "findings": [],
        "started_at": "2024-05-01T12:00:00Z",
        "runtime": {"duration": 1.5},
    }
    auto_path = tmp_path / "results" / "scan.html"
    with (
        mock.patch("reconscript.cli.run_recon", return_value=report),
        mock.patch("reconscript.cli.write_report", return_value=(auto_path, "html")) as mock_writer,
        mock.patch("reconscript.cli.Console") as mock_console,
        mock.patch("reconscript.cli.webbrowser.open", return_value=True) as mock_open,
        mock.patch("reconscript.cli._derive_default_outfile", return_value=auto_path),
    ):
        console_instance = mock.Mock()
        console_instance.print = mock.Mock()
        mock_console.return_value = console_instance
        exit_code = cli.main(["--target", "127.0.0.1"])

    assert exit_code == 0
    mock_writer.assert_called_once_with(report, auto_path, "html")
    mock_open.assert_called_once()


def test_main_respects_no_browser_flag(tmp_path):
    report = {
        "ports": [80],
        "open_ports": [80],
        "findings": [],
        "started_at": "2024-05-01T12:00:00Z",
        "runtime": {"duration": 1.5},
    }
    auto_path = tmp_path / "results" / "scan.html"
    with (
        mock.patch("reconscript.cli.run_recon", return_value=report),
        mock.patch("reconscript.cli.write_report", return_value=(auto_path, "html")),
        mock.patch("reconscript.cli.Console") as mock_console,
        mock.patch("reconscript.cli.webbrowser.open") as mock_open,
        mock.patch("reconscript.cli._derive_default_outfile", return_value=auto_path),
    ):
        console_instance = mock.Mock()
        console_instance.print = mock.Mock()
        mock_console.return_value = console_instance
        cli.main(["--target", "127.0.0.1", "--no-browser"])

    mock_open.assert_not_called()


def _response(url: str, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> Response:
    resp = Response()
    resp.status_code = status
    resp._content = body.encode("utf-8")  # type: ignore[attr-defined]
    resp.url = url
    resp.headers = CaseInsensitiveDict(headers or {})
    resp.history = []
    return resp


class _Session:
    def __init__(self, response: Response):
        self.response = response

    def get(self, url: str, allow_redirects: bool = True) -> Response:
        return self.response


def test_probe_http_service_blocks_external_redirect():
    redirect = _response("http://example.com", status=302)
    final = _response("http://malicious.test/", status=200)
    final.history = [redirect]
    session = _Session(final)

    result = probe_http_service(session, "example.com", 80)

    assert result == {"error": "redirected to external host", "redirect_url": "http://malicious.test/"}


def test_probe_http_service_allows_same_host_redirect():
    redirect = _response("http://example.com", status=302)
    final = _response("http://example.com/welcome", status=200, body="hello", headers={"Content-Type": "text/plain"})
    final.history = [redirect]
    session = _Session(final)

    result = probe_http_service(session, "example.com", 80)

    assert result["status_code"] == 200
    assert result["url"].startswith("http://example.com")


