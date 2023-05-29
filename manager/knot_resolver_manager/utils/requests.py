import socket
from http.client import HTTPConnection
import sys
from typing import Any, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.request import AbstractHTTPHandler, Request, build_opener, install_opener, urlopen

from typing_extensions import Literal


class Response:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body

    def __repr__(self) -> str:
        return f"status: {self.status}\nbody:\n{self.body}"


def request(
    method: Literal["GET", "POST", "HEAD", "PUT", "DELETE"],
    url: str,
    body: Optional[str] = None,
    content_type: str = "application/json",
) -> Response:
    req = Request(
        url,
        method=method,
        data=body.encode("utf8") if body is not None else None,
        headers={"Content-Type": content_type},
    )
    # req.add_header("Authorization", _authorization_header)

    try:
        with urlopen(req) as response:
            return Response(response.status, response.read().decode("utf8"))
    except HTTPError as err:
        return Response(err.code, err.read().decode("utf8"))
    except URLError as err:
        if err.errno == 111 or isinstance(err.reason, ConnectionRefusedError):
            print("Connection refused.")
            print(f"\tURL: {url}")
            print("Is the URL correct?")
            print("\tUnix socket would start with http+unix:// and URL encoded path.")
            print("\tInet sockets would start with http:// and domain or ip")
        else:
            print(f"{err}: url={url}", file=sys.stderr)
        sys.exit(1)


# Code heavily inspired by requests-unixsocket
# https://github.com/msabramo/requests-unixsocket/blob/master/requests_unixsocket/adapters.py
class UnixHTTPConnection(HTTPConnection):
    def __init__(self, unix_socket_url: str, timeout: Union[int, float] = 60):
        """Create an HTTP connection to a unix domain socket
        :param unix_socket_url: A URL with a scheme of 'http+unix' and the
        netloc is a percent-encoded path to a unix domain socket. E.g.:
        'http+unix://%2Ftmp%2Fprofilesvc.sock/status/pid'
        """
        super().__init__("localhost", timeout=timeout)
        self.unix_socket_path = unix_socket_url
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def __del__(self):  # base class does not have d'tor
        if self.sock:
            self.sock.close()

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1)  # there is something weird stored in self.timeout
        sock.connect(self.unix_socket_path)
        self.sock = sock


class UnixHTTPHandler(AbstractHTTPHandler):
    def __init__(self) -> None:
        super().__init__()

        def open_(self: UnixHTTPHandler, req: Any) -> Any:
            return self.do_open(UnixHTTPConnection, req)

        setattr(UnixHTTPHandler, "http+unix_open", open_)
        setattr(UnixHTTPHandler, "http+unix_request", AbstractHTTPHandler.do_request_)


opener = build_opener(UnixHTTPHandler())
install_opener(opener)
