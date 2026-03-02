from __future__ import annotations

import os
import stat
from enum import Flag, auto
from grp import getgrnam
from pwd import getpwnam, getpwuid
from typing import TYPE_CHECKING

from knot_resolver.utils.modeling.context import Context, Strictness
from knot_resolver.utils.modeling.errors import DataValidationError, DataValueError

from .base_path_types import BasePath

if TYPE_CHECKING:
    from pathlib import Path


class Directory(BasePath):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness > Strictness.NORMAL:
            try:
                path = self._path_absolute
                if not path.is_dir():
                    msg = f"path '{path}' does not point to an existing directory"
                    raise DataValueError(msg)
            except PermissionError as e:
                msg = f"insufficient permissions for '{e.filename}'"
                raise DataValidationError(msg, self._tree_path) from None


class File(BasePath):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness > Strictness.BASIC:
            try:
                path = self._path_absolute
                if context.strictness > Strictness.NORMAL and not path.is_file():
                    msg = f"path '{path}' does not point to an existing file"
                    raise DataValueError(msg)
            except PermissionError as e:
                msg = f"insufficient permissions for '{e.filename}'"
                raise DataValidationError(msg, self._tree_path) from None


class FilePath(BasePath):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness > Strictness.BASIC:
            try:
                path = self._path_absolute
                if context.strictness > Strictness.NORMAL:
                    parent = path.parent
                    if not parent.is_dir():
                        msg = f"parent '{parent}' does not point an existing directory"
                        raise DataValueError(msg)
                    if path.is_dir():
                        msg = f"path '{path}' points to a directory when we expected a file"
                        raise DataValueError(msg)
            except PermissionError as e:
                msg = f"insufficient permissions for '{e.filename}'"
                raise DataValidationError(msg, self._tree_path) from None


class _PermissionMode(Flag):
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()


def _check_path_permission(context: Context, dest_path: Path, perm_mode: _PermissionMode) -> bool:
    chflags = {
        _PermissionMode.READ: [stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH],
        _PermissionMode.WRITE: [stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH],
        _PermissionMode.EXECUTE: [stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH],
    }

    # running outside (client, ...)
    if context.username and context.groupname:
        user_uid = getpwnam(context.username).pw_uid
        user_gid = getgrnam(context.groupname).gr_gid
        username = context.username
    # running under root privileges
    elif os.geteuid() == 0:
        return True
    # running normally under an unprivileged user
    else:
        user_uid = os.getuid()
        user_gid = os.getgid()
        username = getpwuid(user_uid).pw_name

    try:
        dest_stat = dest_path.stat()
    except PermissionError:
        return False

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
    return all(not (perm in perm_mode and not accessible(perm)) for perm in _PermissionMode)


class ReadableFile(File):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness is Strictness.STRICT:
            path = self._path_absolute
            msg = f"insufficient permissions to read '{path}'"
            if not (_check_path_permission(context, path, _PermissionMode.READ) or os.access(self._value, os.R_OK)):
                raise DataValidationError(msg, self._tree_path)


class WritableDirectory(Directory):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness is Strictness.STRICT:
            path = self._path_absolute
            if not (
                _check_path_permission(context, path, _PermissionMode.WRITE | _PermissionMode.EXECUTE)
                and os.access(path.parent, os.W_OK | os.X_OK)
            ):
                msg = f"insufficient permissions to write/execute '{path}'"
                raise DataValidationError(msg, self._tree_path)


class WritableFilePath(FilePath):
    def _validate(self, context: Context) -> None:
        super()._validate(context)

        if context.strictness is Strictness.STRICT:
            path = self._path_absolute
            # check that parent dir is writable
            if not (
                _check_path_permission(context, path.parent, _PermissionMode.WRITE | _PermissionMode.EXECUTE)
                or os.access(path.parent, os.W_OK | os.X_OK)
            ):
                msg = f"insufficient permissions to write/execute '{path.parent}'"
                raise DataValidationError(msg, self._tree_path)
            # check that existing file is writable
            if path.exists() and not (
                _check_path_permission(context, path, _PermissionMode.WRITE | _PermissionMode.EXECUTE)
                or os.access(path, os.W_OK)
            ):
                msg = f"insufficient permissions to write/execute '{path}'"
                raise DataValidationError(msg, self._tree_path)
