import copy
from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from typing import Any, List, Literal, Optional, Tuple, Union

from knot_resolver.utils.modeling.base_schema import BaseSchema, map_object
from knot_resolver.utils.modeling.json_pointer import json_ptr_resolve


class PatchError(Exception):
    pass


class Op(BaseSchema, ABC):
    @abstractmethod
    def eval(self, fakeroot: Any) -> Any:
        """
        modifies the given fakeroot, returns a new one
        """

    def _resolve_ptr(self, fakeroot: Any, ptr: str) -> Tuple[Any, Any, Union[str, int, None]]:
        # Lookup tree part based on the given JSON pointer
        parent, obj, token = json_ptr_resolve(fakeroot["root"], ptr)

        # the lookup was on pure data, wrap the results in QueryTree
        if parent is None:
            parent = fakeroot
            token = "root"

        assert token is not None

        return parent, obj, token


class AddOp(Op):
    op: Literal["add"]
    path: str
    value: Any

    def eval(self, fakeroot: Any) -> Any:
        parent, _obj, token = self._resolve_ptr(fakeroot, self.path)

        if isinstance(parent, dict):
            parent[token] = self.value
        elif isinstance(parent, list):
            if token == "-":
                parent.append(self.value)
            else:
                assert isinstance(token, int)
                parent.insert(token, self.value)
        else:
            assert False, "never happens"

        return fakeroot


class RemoveOp(Op):
    op: Literal["remove"]
    path: str

    def eval(self, fakeroot: Any) -> Any:
        parent, _obj, token = self._resolve_ptr(fakeroot, self.path)
        del parent[token]
        return fakeroot


class ReplaceOp(Op):
    op: Literal["replace"]
    path: str
    value: str

    def eval(self, fakeroot: Any) -> Any:
        parent, obj, token = self._resolve_ptr(fakeroot, self.path)

        if obj is None:
            raise PatchError("the value you are trying to replace is null")
        parent[token] = self.value
        return fakeroot


class MoveOp(Op):
    op: Literal["move"]
    source: str
    path: str

    def _source(self, source):
        if "from" not in source:
            raise ValueError("missing property 'from' in 'move' JSON patch operation")
        return str(source["from"])

    def eval(self, fakeroot: Any) -> Any:
        if self.path.startswith(self.source):
            raise PatchError("can't move value into itself")

        _parent, obj, _token = self._resolve_ptr(fakeroot, self.source)
        newobj = copy.deepcopy(obj)

        fakeroot = RemoveOp({"op": "remove", "path": self.source}).eval(fakeroot)
        fakeroot = AddOp({"path": self.path, "value": newobj, "op": "add"}).eval(fakeroot)
        return fakeroot


class CopyOp(Op):
    op: Literal["copy"]
    source: str
    path: str

    def _source(self, source):
        if "from" not in source:
            raise ValueError("missing property 'from' in 'copy' JSON patch operation")
        return str(source["from"])

    def eval(self, fakeroot: Any) -> Any:
        _parent, obj, _token = self._resolve_ptr(fakeroot, self.source)
        newobj = copy.deepcopy(obj)

        fakeroot = AddOp({"path": self.path, "value": newobj, "op": "add"}).eval(fakeroot)
        return fakeroot


class TestOp(Op):
    op: Literal["test"]
    path: str
    value: Any

    def eval(self, fakeroot: Any) -> Any:
        _parent, obj, _token = self._resolve_ptr(fakeroot, self.path)

        if obj != self.value:
            raise PatchError("test failed")

        return fakeroot


def query(
    original: Any, method: Literal["get", "delete", "put", "patch"], ptr: str, payload: Any
) -> Tuple[Any, Optional[Any]]:
    ########################################
    # Prepare data we will be working on

    # First of all, we consider the original data to be immutable. So we need to make a copy
    # in order to freely mutate them
    dataroot = copy.deepcopy(original)

    # To simplify referencing the root, create a fake root node
    fakeroot = {"root": dataroot}

    #########################################
    # Handle the actual requested operation

    # get = return what the path selector picks
    if method == "get":
        parent, obj, token = json_ptr_resolve(fakeroot, f"/root{ptr}")
        return fakeroot["root"], obj

    elif method == "delete":
        fakeroot = RemoveOp({"op": "remove", "path": ptr}).eval(fakeroot)
        return fakeroot["root"], None

    elif method == "put":
        parent, obj, token = json_ptr_resolve(fakeroot, f"/root{ptr}")
        assert parent is not None  # we know this due to the fakeroot
        if isinstance(parent, list) and token == "-":
            parent.append(payload)
        else:
            parent[token] = payload
        return fakeroot["root"], None

    elif method == "patch":
        tp = List[Union[AddOp, RemoveOp, MoveOp, CopyOp, TestOp, ReplaceOp]]
        transaction: tp = map_object(tp, payload)

        for i, op in enumerate(transaction):
            try:
                fakeroot = op.eval(fakeroot)
            except PatchError as e:
                raise ValueError(f"json patch transaction failed on step {i}") from e

        return fakeroot["root"], None

    else:
        assert False, "invalid operation, never happens"
