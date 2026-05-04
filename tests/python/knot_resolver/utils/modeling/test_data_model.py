import pytest

# from typing import Any

from knot_resolver.utils.modeling.data_model import DataModel
# from knot_resolver.utils.modeling.errors import DataDescriptionError
from knot_resolver.utils.modeling.parsing import try_to_parse_file



class TestModel(DataModel):
    test: str = "default value"






# class NoDescription(DataModelNode):
#     pass


# class SingleLineDescription(DataModelNode):
#     """
#     Single line description.
#     """


# class MultiLineDescription(DataModelNode):
#     """
#     Multi line
#     description.
#     """


# class AttributesDescription(DataModelNode):
#     """
#     Data model node description.
#     ---
#     integer_attr: Description for the integer attribute.
#     string_attr: Description for the string attribute.
#     """

#     integer: int
#     string: str


@pytest.mark.parametrize("model", [TestModel])
def test_data_model(model: DataModel):
    parsed_data = try_to_parse_file("/home/amrazek/src/knot-resolver/tests/python/knot_resolver/utils/modeling/config.test.yaml")
    modeled = TestModel(parsed_data)

    assert modeled.test == "this is test"


# @pytest.mark.parametrize("model", [AttributesDescription])
# def test_json_schema(model: Any):
#     schema = model.json_schema()


# @pytest.mark.parametrize("model", [NoDescription, SingleLineDescription, MultiLineDescription])
# def test_json_schema_invalid(model: Any):
#     with pytest.raises(DataDescriptionError):
#         model.json_schema()


# #     class FieldsDescription(ConfigSchema):
# #         """
# #         This is an awesome test class
# #         ---
# #         field: This field does nothing interesting
# #         value: Neither does this
# #         """

# #         field: str
# #         value: int

# #     schema = FieldsDescription.json_schema()
# #     assert schema["description"] == "This is an awesome test class"
# #     assert schema["properties"]["field"]["description"] == "This field does nothing interesting"
# #     assert schema["properties"]["value"]["description"] == "Neither does this"

# #     class NoDescription(ConfigSchema):
# #         nothing: str

# #     _ = NoDescription.json_schema()


# # def test_docstring_parsing_invalid():
# #     class AdditionalItem(ConfigSchema):
# #         """
# #         This class is wrong
# #         ---
# #         field: nope
# #         nothing: really nothing
# #         """

# #         nothing: str

# #     with raises(DataDescriptionError):
# #         _ = AdditionalItem.json_schema()

# #     class WrongDescription(ConfigSchema):
# #         """
# #         This class is wrong
# #         ---
# #         other: description
# #         """

# #         nothing: str

# #     with raises(DataDescriptionError):
# #         _ = WrongDescription.json_schema()
