import copy
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from typing_extensions import Literal

from knot_resolver_manager.utils.modeling.exceptions import DataParsingError


class QueryTree:
    """
    Simple wrapper for raw data which allows modification queries to be run on top.

    IMMUTABLE, DO NOT MODIFY
    """

    def is_scalar(self) -> bool:
        """
        true if the object represents a primitive type
        """
        return isinstance(self._data, (str, int, bool))

    def is_object(self) -> bool:
        """
        true if the object represents a list or dict
        """
        return isinstance(self._data, (list, dict))

    def _is_list(self) -> bool:
        return isinstance(self._data, list)

    def _is_dict(self) -> bool:
        return isinstance(self._data, dict)

    def _upsert(self, key: str, value: "QueryTree") -> None:
        """
        WARNING!!! MUTATES THE TREE

        update or insert
        """
        if isinstance(self._data, dict):
            self._data[key] = value.to_raw()
        elif isinstance(self._data, list):
            if key in self:
                self._data[int(key)] = value.to_raw()
            else:
                raise DataParsingError("query invalid: can't set a value of an item in a list at a non-existent index")
        else:
            assert False, "this should never happen"

    def _append(self, value: "QueryTree") -> None:
        """
        WARNING!!! MUTATES THE TREE

        append to a list
        """
        assert isinstance(self._data, list)
        self._data.append(value.to_raw())

    def _delete(self, key: str) -> None:
        """
        WARNING!!! MUTATES THE TREE

        deletes a key
        """
        assert self.is_object()
        if isinstance(self._data, list):
            del self._data[int(key)]
        elif isinstance(self._data, dict):
            del self._data[key]
        else:
            assert False, "never happens"

    def value(self) -> Union[str, int, bool]:
        if self.is_object():
            raise DataParsingError("attempted to access object as a scalar")

        assert isinstance(self._data, (str, int, bool))  # make type checker happy
        return self._data

    def __init__(self, data: Union[Dict[str, Any], str, int, bool, List[Any]]):
        self._data = data

    def to_raw(self) -> Union[Dict[str, Any], str, int, bool, List[Any]]:
        return self._data

    def __getitem__(self, key: Union[str, int]) -> "QueryTree":
        if self.is_scalar():
            raise DataParsingError(f"attempted to access scalar value '{self._data}' as an object type")

        if isinstance(self._data, list):
            return QueryTree(self._data[int(key)])
        elif isinstance(self._data, dict):
            return QueryTree(self._data[str(key)])
        else:
            raise RuntimeError("unexpected type in self._data, this should never happen")

    def __contains__(self, key: Union[str, int]) -> bool:
        if self.is_scalar():
            raise DataParsingError(f"attempted to access scalar value '{self._data}' as an object type")

        if isinstance(self._data, list):
            return int(key) < len(self._data)
        elif isinstance(self._data, dict):
            return key in self._data
        else:
            raise RuntimeError("unexpected type in self._data, this should never happen")

    def __str__(self) -> str:
        return json.dumps(self._data, sort_keys=False, indent=2)

    def keys(self) -> Set[Any]:
        if self.is_scalar():
            raise DataParsingError(f"attempted to access scalar value '{self._data}' as an object type")

        if isinstance(self._data, dict):
            return set(self._data.keys())
        elif isinstance(self._data, list):
            return set(range(len(self._data)))
        else:
            raise RuntimeError("unexpected type in self._data, this should never happen")

    _SUBTREE_MUTATION_PATH_PATTERN = re.compile(r"^(/[^/]+)*/?$")

    def _preprocess_query_path(self, path: str) -> str:
        # prepare and validate the path object
        path = path[:-1] if path.endswith("/") else path
        if re.match(QueryTree._SUBTREE_MUTATION_PATH_PATTERN, path) is None:
            raise DataParsingError("Provided object path for mutation is invalid.")
        if "_" in path:
            raise DataParsingError("Provided object path contains character '_', which is illegal")

        # now, the path variable should contain '/' separated field names
        return path.strip("/")

    def _copy_and_find(self, path: str) -> Tuple["QueryTree", "QueryTree", Optional["QueryTree"], str]:
        """
        Returns (fakeroot, parent, Optional[queryTarget])

        - fakeroot has the real root in a field called 'root'
        - queryTarget is None, when it refers to non-existent object
        """

        path = self._preprocess_query_path(path)

        # `self` is considered immutable, do all operations on a copy
        rwcopy = copy.deepcopy(self)
        # make a fake root, so that we do not have to handle special cases for root node
        rwcopy._data = {"root": rwcopy._data}  # pylint: disable=protected-access
        segments = f"root/{path}".strip("/").split("/")

        # walk the tree
        obj: Optional[QueryTree] = rwcopy
        parent: QueryTree = rwcopy
        segment = ""  # just to make type checker happy
        for segment in segments:
            assert len(segment) > 0
            if obj is None:
                raise DataParsingError(
                    f"query path does not point to any existing object in the configuration tree, first missing path segment is called '{segment}'"
                )
            elif segment in obj:
                parent = obj
                obj = obj[segment]
            else:
                parent = obj
                obj = None

        return rwcopy, parent, obj, segment

    @staticmethod
    def _post(
        fakeroot: "QueryTree",
        parent: "QueryTree",
        obj: Optional["QueryTree"],
        name: str,
        update_with: Optional["QueryTree"] = None,
    ) -> "Tuple[QueryTree, Optional[QueryTree]]":
        # pylint: disable=protected-access
        if update_with is None:
            raise DataParsingError("query invalid: can't request a change via POST and not provide a value")
        if parent._is_dict():
            parent._upsert(name, update_with)
            return fakeroot["root"], None
        elif parent._is_list():
            if obj is None:
                parent._append(update_with)
                return fakeroot["root"], None
            else:
                parent._upsert(name, update_with)
                return fakeroot["root"], None
        else:
            assert False, "this should never happen"

    @staticmethod
    def _patch(
        fakeroot: "QueryTree",
        parent: "QueryTree",
        obj: Optional["QueryTree"],
        name: str,
        update_with: Optional["QueryTree"] = None,
    ) -> "Tuple[QueryTree, Optional[QueryTree]]":
        # pylint: disable=protected-access
        if update_with is None:
            raise DataParsingError("query invalid: can't request a change via PATCH and not provide a value")
        if obj is None:
            raise DataParsingError("query error: can't update non-existent object")
        else:
            parent._upsert(name, update_with)
            return fakeroot["root"], None

    @staticmethod
    def _put(
        fakeroot: "QueryTree",
        parent: "QueryTree",
        obj: Optional["QueryTree"],
        name: str,
        update_with: Optional["QueryTree"] = None,
    ) -> "Tuple[QueryTree, Optional[QueryTree]]":
        # pylint: disable=protected-access
        if update_with is None:
            raise DataParsingError("query invalid: can't request an insert via PUT and not provide a value")
        if obj is None:
            if parent._is_list():
                parent._append(update_with)
                return fakeroot["root"], None
            elif parent._is_dict():
                parent._upsert(name, update_with)
                return fakeroot["root"], None
            else:
                assert False, "never happens"
        else:
            raise DataParsingError("query invalid: can't insert when there is already a value there")

    def query(
        self, op: Literal["get", "post", "delete", "patch", "put"], path: str, update_with: Optional["QueryTree"] = None
    ) -> "Tuple[QueryTree, Optional[QueryTree]]":
        """
        Implements a modification API in the style of Caddy:
            https://caddyserver.com/docs/api
        """
        # pylint: disable=protected-access
        fakeroot, parent, obj, name = self._copy_and_find(path)

        # get = return what the path selector picks
        if op == "get":
            return fakeroot["root"], obj

        # post = set value at a key, append to lists
        elif op == "post":
            return self._post(fakeroot, parent, obj, name, update_with)

        # delete = remove the given key
        elif op == "delete":
            parent._delete(name)
            return fakeroot["root"], None

        # patch = update an existing object
        elif op == "patch":
            return self._patch(fakeroot, parent, obj, name, update_with)

        # put = insert and never replace
        elif op == "put":
            return self._put(fakeroot, parent, obj, name, update_with)

        else:
            assert False, "invalid operation"
