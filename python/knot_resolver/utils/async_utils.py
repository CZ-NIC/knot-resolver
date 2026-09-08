from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


async def readfile(path: Path) -> str:
    """Asynchronously read the file at path and return its content."""
    return await asyncio.to_thread(path.read_text, encoding="utf-8")


async def writefile(path: Path, content: str) -> None:
    """Asynchronously write content to the file at path."""
    await asyncio.to_thread(path.write_text, content, encoding="utf-8")
