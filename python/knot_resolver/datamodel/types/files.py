import logging
import os
import stat
from enum import Flag, auto
from grp import getgrnam
from pathlib import Path
from pwd import getpwnam, getpwuid
from typing import Any, Dict, Tuple, Type, TypeVar

from knot_resolver.constants import GROUP, USER
from knot_resolver.datamodel.globals import get_permissions_default, get_resolve_root, get_strict_validation
from knot_resolver.utils.modeling.base_value_type import BaseValueType

logger = logging.getLogger(__name__)


class UncheckedPath(BaseValueType):
    """
    Wrapper around pathlib.Path object. Can represent pretty much any Path. No checks are
    performed on the value. The value is taken as is.
    """

    _value: Path

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        self._object_path: str = object_path
        self._parents: Tuple[UncheckedPath, ...] = parents
        self.strict_validation: bool = get_strict_validation()

        if isinstance(source_value, str):
            # we do not load global validation context if the path is absolute
            # this prevents errors when constructing defaults in the schema
            if source_value.startswith("/"):
                resolve_root = Path("/")
            else:
                resolve_root = get_resolve_root()

            self._raw_value: str = source_value
            if self._parents:
                pp = map(lambda p: p.to_path(), self._parents)
                self._value: Path = Path(resolve_root, *pp, source_value)
            else:
                self._value: Path = Path(resolve_root, source_value)
        else:
            raise ValueError(f"expected file path in a string, got '{source_value}' with type '{type(source_value)}'.")

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, UncheckedPath):
            return False

        return o._value == self._value

    def __int__(self) -> int:
        raise RuntimeError("Path cannot be converted to type <int>")

    def to_path(self) -> Path:
        return self._value

    def serialize(self) -> Any:
        return self._raw_value

    def relative_to(self, parent: "UncheckedPath") -> "UncheckedPath":
        """return a path with an added parent part"""
        return UncheckedPath(self._raw_value, parents=(parent, *self._parents), object_path=self._object_path)

    UPT = TypeVar("UPT", bound="UncheckedPath")

    def reconstruct(self, cls: Type[UPT]) -> UPT:
        """
        Rebuild this object as an instance of its subclass. Practically, allows for conversions from
        """
        return cls(self._raw_value, parents=self._parents, object_path=self._object_path)

    @classmethod
    def json_schema(cls: Type["UncheckedPath"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class Dir(UncheckedPath):
    """
    Path, that is enforced to be:
    - an existing directory
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        try:
            super().__init__(source_value, parents=parents, object_path=object_path)
            if self.strict_validation and not self._value.is_dir():
                raise ValueError(f"path '{self._value}' does not point to an existing directory")
        except PermissionError as e:
            raise ValueError(str(e)) from e


class AbsoluteDir(Dir):
    """
    Path, that is enforced to be:
    - absolute
    - an existing directory
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        if self.strict_validation and not self._value.is_absolute():
            raise ValueError(f"path '{self._value}' is not absolute")


class File(UncheckedPath):
    """
    Path, that is enforced to be:
    - an existing file
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        try:
            super().__init__(source_value, parents=parents, object_path=object_path)
            if self.strict_validation and not self._value.exists():
                raise ValueError(f"file '{self._value}' does not exist")
            if self.strict_validation and not self._value.is_file():
                raise ValueError(f"path '{self._value}' is not a file")
        except PermissionError as e:
            raise ValueError(str(e)) from e


class FilePath(UncheckedPath):
    """
    Path, that is enforced to be:
    - parent of the last path segment is an existing directory
    - it does not point to a dir
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        try:
            super().__init__(source_value, parents=parents, object_path=object_path)
            p = self._value.parent
            if self.strict_validation and (not p.exists() or not p.is_dir()):
                raise ValueError(f"path '{self._value}' does not point inside an existing directory")
            if self.strict_validation and self._value.is_dir():
                raise ValueError(f"path '{self._value}' points to a directory when we expected a file")
        except PermissionError as e:
            raise ValueError(str(e)) from e


class _PermissionMode(Flag):
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()


def _check_permission(dest_path: Path, perm_mode: _PermissionMode) -> bool:
    chflags = {
        _PermissionMode.READ: [stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH],
        _PermissionMode.WRITE: [stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH],
        _PermissionMode.EXECUTE: [stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH],
    }

    if get_permissions_default():
        user_uid = getpwnam(USER).pw_uid
        user_gid = getgrnam(GROUP).gr_gid
        username = USER
    else:
        user_uid = os.getuid()
        user_gid = os.getgid()
        username = getpwuid(user_uid).pw_name

    dest_stat = os.stat(dest_path)
    dest_uid = dest_stat.st_uid
    dest_gid = dest_stat.st_gid
    dest_mode = dest_stat.st_mode

    def accessible(perm: _PermissionMode) -> bool:
        if user_uid == dest_uid:
            return bool(dest_mode & chflags[perm][0])
        b_groups = os.getgrouplist(username, user_gid)
        if user_gid == dest_gid or dest_gid in b_groups:
            return bool(dest_mode & chflags[perm][1])
        return bool(dest_mode & chflags[perm][2])

    # __iter__ for class enum.Flag added in python3.11
    # 'for perm in perm_mode:' fails for <=python3.11
    for perm in _PermissionMode:
        if perm in perm_mode:
            if not accessible(perm):
                return False
    return True


class ReadableFile(File):
    """
    Path, that is enforced to be:
    - an existing file
    - readable by knot-resolver processes
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)

        if self.strict_validation and not _check_permission(self._value, _PermissionMode.READ):
            msg = f"{USER}:{GROUP} has insufficient permissions to read '{self._value}'"
            if not os.access(self._value, os.R_OK):
                raise ValueError(msg)
            logger.info(f"{msg}, but the resolver can somehow (ACLs, ...) read the file")


class WritableDir(Dir):
    """
    Path, that is enforced to be:
    - an existing directory
    - writable/executable by knot-resolver processes
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)

        if self.strict_validation and not _check_permission(
            self._value, _PermissionMode.WRITE | _PermissionMode.EXECUTE
        ):
            msg = f"{USER}:{GROUP} has insufficient permissions to write/execute '{self._value}'"
            if not os.access(self._value, os.W_OK | os.X_OK):
                raise ValueError(msg)
            logger.info(f"{msg}, but the resolver can somehow (ACLs, ...) write to the directory")


class WritableFilePath(FilePath):
    """
    Path, that is enforced to be:
    - parent of the last path segment is an existing directory
    - it does not point to a dir
    - writable/executable parent directory by knot-resolver processes
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)

        if self.strict_validation:
            # check that parent dir is writable
            if not _check_permission(self._value.parent, _PermissionMode.WRITE | _PermissionMode.EXECUTE):
                msg = f"{USER}:{GROUP} has insufficient permissions to write/execute '{self._value.parent}'"
                # os.access() on the dir just provides a more precise message,
                # as the os.access() on the file below check everything in one go
                if not os.access(self._value.parent, os.W_OK | os.X_OK):
                    raise ValueError(msg)
                logger.info(f"{msg}, but the resolver can somehow (ACLs, ...) write to the directory")

            # check that existing file is writable
            if self._value.exists() and not _check_permission(self._value, _PermissionMode.WRITE):
                msg = f"{USER}:{GROUP} has insufficient permissions to write/execute '{self._value}'"
                if not os.access(self._value, os.W_OK):
                    raise ValueError(msg)
                logger.info(f"{msg}, but the resolver can somehow (ACLs, ...) write to the file")
