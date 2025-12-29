import errno
import socket
import sys
from http.client import HTTPConnection
from typing import Any, Literal, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import AbstractHTTPHandler, Request, build_opener, install_opener, urlopen


class SocketDesc:
    def __init__(self, socket_def: str, source: str) -> None:
        self.source = source
        if ":" in socket_def:
            # `socket_def` contains a schema, probably already URI-formatted, use directly
            self.uri = socket_def
        else:
            # `socket_def` is probably a path, convert to URI
            self.uri = f'http+unix://{quote(socket_def, safe="")}'

        while self.uri.endswith("/"):
            self.uri = self.uri[:-1]


class Response:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body

    def __repr__(self) -> str:
        return f"status: {self.status}\nbody:\n{self.body}"


def _print_conn_error(error_desc: str, url: str, socket_source: str) -> None:
    host: str
    try:
        parsed_url = urlparse(url)
        host = unquote(parsed_url.hostname or "(Unknown)")
    except ValueError as e:
        host = f"(Invalid URL: {e})"
    msg = f"""
{error_desc}
\tURL:           {url}
\tHost/Path:     {host}
\tSourced from:  {socket_source}
Is the URL correct?
\tUnix socket would start with http+unix:// and URL encoded path.
\tInet sockets would start with http:// and domain or ip
    """
    print(msg, file=sys.stderr)


def request(
    socket_desc: SocketDesc,
    method: Literal["GET", "POST", "HEAD", "PUT", "DELETE"],
    path: str,
    body: Optional[str] = None,
    content_type: str = "application/json",
) -> Response:
    while path.startswith("/"):
        path = path[1:]
    url = f"{socket_desc.uri}/{path}"

    req = Request(
        url,
        method=method,
        data=body.encode("utf8") if body is not None else None,
        headers={"Content-Type": content_type},
    )

    timeout_m = 5  # minutes
    try:
        with urlopen(req, timeout=timeout_m * 60) as response:
            return Response(response.status, response.read().decode("utf8"))
    except HTTPError as err:
        return Response(err.code, err.read().decode("utf8"))
    except URLError as err:
        if err.errno == errno.ECONNREFUSED or isinstance(err.reason, ConnectionRefusedError):
            _print_conn_error("Connection refused.", url, socket_desc.source)
        elif err.errno == errno.ENOENT or isinstance(err.reason, FileNotFoundError):
            _print_conn_error("No such file or directory.", url, socket_desc.source)
        else:
            _print_conn_error(str(err), url, socket_desc.source)
        sys.exit(1)
    except (TimeoutError, socket.timeout):
        _print_conn_error(
            f"Connection timed out after {timeout_m} minutes."
            "\nIt does not mean that the operation necessarily failed."
            "\nSee Knot Resolver's log for more information.",
            url,
            socket_desc.source,
        )
        sys.exit(1)


# Code heavily inspired by requests-unixsocket
# https://github.com/msabramo/requests-unixsocket/blob/master/requests_unixsocket/adapters.py
class UnixHTTPConnection(HTTPConnection):
    def __init__(self, unix_socket_url: str, timeout: float = 60) -> None:
        """
        Create an HTTP connection to a unix domain socket.

        Args:
            unix_socket_url (str): A URL with a scheme of 'http+unix' and the netloc is a percent-encoded path
                to a unix domain socket. E.g.: 'http+unix://%2Ftmp%2Fprofilesvc.sock/status/pid'
            timeout (float): Connection timeout.

        """
        super().__init__("localhost", timeout=timeout)
        self.unix_socket_path = unix_socket_url
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def __del__(self) -> None:  # base class does not have d'tor
        if self.sock:
            self.sock.close()

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_socket_path)
        self.sock = sock


class UnixHTTPHandler(AbstractHTTPHandler):
    def __init__(self) -> None:
        super().__init__()

        def open_(self: UnixHTTPHandler, req: Any) -> Any:
            return self.do_open(UnixHTTPConnection, req)  # type: ignore[arg-type]

        setattr(UnixHTTPHandler, "http+unix_open", open_)
        setattr(UnixHTTPHandler, "http+unix_request", AbstractHTTPHandler.do_request_)


opener = build_opener(UnixHTTPHandler())
install_opener(opener)
