import base64
import json
from hashlib import blake2b
from typing import Any


def structural_etag(obj: Any) -> str:
    m = blake2b(digest_size=15)
    m.update(json.dumps(obj, sort_keys=True).encode("utf8"))
    return base64.urlsafe_b64encode(m.digest()).decode("utf8")
