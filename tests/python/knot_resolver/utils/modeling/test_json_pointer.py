from pytest import raises

from knot_resolver.utils.modeling.json_pointer import json_ptr_resolve

# example adopted from https://www.sitepoint.com/json-server-example/
TEST = {
    "clients": [
        {
            "id": "59761c23b30d971669fb42ff",
            "isActive": True,
            "age": 36,
            "name": "Dunlap Hubbard",
            "gender": "male",
            "company": "CEDWARD",
            "email": "dunlaphubbard@cedward.com",
            "phone": "+1 (890) 543-2508",
            "address": "169 Rutledge Street, Konterra, Northern Mariana Islands, 8551",
        },
        {
            "id": "59761c233d8d0f92a6b0570d",
            "isActive": True,
            "age": 24,
            "name": "Kirsten Sellers",
            "gender": "female",
            "company": "EMERGENT",
            "email": "kirstensellers@emergent.com",
            "phone": "+1 (831) 564-2190",
            "address": "886 Gallatin Place, Fannett, Arkansas, 4656",
        },
        {
            "id": "59761c23fcb6254b1a06dad5",
            "isActive": True,
            "age": 30,
            "name": "Acosta Robbins",
            "gender": "male",
            "company": "ORGANICA",
            "email": "acostarobbins@organica.com",
            "phone": "+1 (882) 441-3367",
            "address": "697 Linden Boulevard, Sattley, Idaho, 1035",
        },
    ]
}


def test_json_ptr():
    parent, res, token = json_ptr_resolve(TEST, "")
    assert parent is None
    assert res is TEST

    parent, res, token = json_ptr_resolve(TEST, "/")
    assert parent is TEST
    assert res is None
    assert token == ""

    parent, res, token = json_ptr_resolve(TEST, "/clients/2/gender")
    assert parent is TEST["clients"][2]
    assert res == "male"
    assert token == "gender"

    with raises(ValueError):
        _ = json_ptr_resolve(TEST, "//")

    with raises(SyntaxError):
        _ = json_ptr_resolve(TEST, "invalid/ptr")

    with raises(ValueError):
        _ = json_ptr_resolve(TEST, "/clients/2/gender/invalid")

    parent, res, token = json_ptr_resolve(TEST, "/~01")
    assert parent is TEST
    assert res is None
    assert token == "~1"
