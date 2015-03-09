import pytest

from ..protocol import Message, FiniteStream
from ..exception import DeserializationException


class TestMessage(object):
    """Message (de)serialization test."""

    # data definitions for test of de(serialization)
    # serialized messages holding a section
    ser_sec_unclosed = b"\x01\x08unclosed"
    ser_sec_single = b"\x01\x07section\x02"
    ser_sec_nested = b"\x01\x05outer\x01\x0asubsection\x02\x02"

    # serialized messages holding a list
    ser_list_invalid = b"\x04\x07invalid\x05\x00\x02e1\x02\x03sec\x06"
    ser_list_0_item = b"\x04\x05empty\x06"
    ser_list_1_item = b"\x04\x01l\x05\x00\x02e1\x06"
    ser_list_2_item = b"\x04\x01l\x05\x00\x02e1\x05\x00\x02e2\x06"

    # serialized messages with key value pairs
    ser_kv_pair = b"\x03\x03key\x00\x05value"
    ser_kv_zero = b"\x03\x0azerolength\x00\x00"

    # deserialized messages holding a section
    des_sec_single = { "section": {} }
    des_sec_nested = { "outer": { "subsection": {} } }

    # deserialized messages holding a list
    des_list_0_item = { "empty": [] }
    des_list_1_item = { "l": [ b"e1" ] }
    des_list_2_item = { "l": [ b"e1", b"e2" ] }

    # deserialized messages with key value pairs
    des_kv_pair = { "key": b"value" }
    des_kv_zero = { "zerolength": b"" }

    def test_section_serialization(self):
        assert Message.serialize(self.des_sec_single) == self.ser_sec_single
        assert Message.serialize(self.des_sec_nested) == self.ser_sec_nested

    def test_list_serialization(self):
        assert Message.serialize(self.des_list_0_item) == self.ser_list_0_item
        assert Message.serialize(self.des_list_1_item) == self.ser_list_1_item
        assert Message.serialize(self.des_list_2_item) == self.ser_list_2_item

    def test_key_serialization(self):
        assert Message.serialize(self.des_kv_pair) == self.ser_kv_pair
        assert Message.serialize(self.des_kv_zero) == self.ser_kv_zero

    def test_section_deserialization(self):
        single = Message.deserialize(FiniteStream(self.ser_sec_single))
        nested = Message.deserialize(FiniteStream(self.ser_sec_nested)) 

        assert single == self.des_sec_single
        assert nested == self.des_sec_nested

        with pytest.raises(DeserializationException):
            Message.deserialize(FiniteStream(self.ser_sec_unclosed))

    def test_list_deserialization(self):
        l0 = Message.deserialize(FiniteStream(self.ser_list_0_item))
        l1 = Message.deserialize(FiniteStream(self.ser_list_1_item))
        l2 = Message.deserialize(FiniteStream(self.ser_list_2_item))

        assert l0 == self.des_list_0_item
        assert l1 == self.des_list_1_item
        assert l2 == self.des_list_2_item

        with pytest.raises(DeserializationException):
            Message.deserialize(FiniteStream(self.ser_list_invalid))

    def test_key_deserialization(self):
        pair = Message.deserialize(FiniteStream(self.ser_kv_pair))
        zerolength = Message.deserialize(FiniteStream(self.ser_kv_zero))

        assert pair == self.des_kv_pair
        assert zerolength == self.des_kv_zero

    def test_roundtrip(self):
        message = {
            "key1": "value1",
            "section1": {
                "sub-section": {
                    "key2": b"value2",
                },
                "list1": [ "item1", "item2" ],
            },
        }
        serialized_message = FiniteStream(Message.serialize(message))
        deserialized_message = Message.deserialize(serialized_message)

        # ensure that list items and key values remain as undecoded bytes
        deserialized_section = deserialized_message["section1"]
        assert deserialized_message["key1"] == b"value1"
        assert deserialized_section["sub-section"]["key2"] == b"value2"
        assert deserialized_section["list1"] == [ b"item1", b"item2" ]