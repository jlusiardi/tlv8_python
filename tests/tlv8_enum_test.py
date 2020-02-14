#
# Copyright 2020 Joachim Lusiardi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import unittest
import enum

import tlv8


class TestTLV8Enum(unittest.TestCase):
    def test_decode_enum(self):

        class TestKeys(enum.IntEnum):
            KEY_1 = 1
            KEY_2 = 2

        class TestValues(enum.IntEnum):
            VALUE_1 = 1
            VALUE_2 = 2

        data = b'\x01\x01\x02'
        result = tlv8.decode(data, {
            TestKeys.KEY_1: TestValues
        })
        expected = [
            tlv8.Entry(TestKeys.KEY_1, TestValues.VALUE_2)
        ]
        self.assertIsInstance(result[0].type_id, TestKeys)
        self.assertIsInstance(result[0].data, TestValues)
        self.assertEqual(expected, result)

    def test_decode_key(self):
        class TestKeys(enum.IntEnum):
            KEY_1 = 1
            KEY_2 = 2
        data = b'\x01\x03foo'
        result = tlv8.decode(data, {
            TestKeys.KEY_1: tlv8.DataType.STRING
        })
        expected = [
            tlv8.Entry(TestKeys.KEY_1, 'foo')
        ]
        self.assertIsInstance(result[0].type_id, TestKeys)
        self.assertEqual(expected, result)

    def test_decode_value(self):
        class TestValues(enum.IntEnum):
            VALUE_1 = 1
            VALUE_2 = 2
        data = b'\x01\x01\x02'
        result = tlv8.decode(data, {
            1: TestValues
        })
        expected = [
            tlv8.Entry(1, 2)
        ]
        self.assertIsInstance(result[0].data, TestValues)
        self.assertEqual(expected, result)

    def test_encode_key(self):
        class TestKeys(enum.IntEnum):
            KEY_1 = 1
            KEY_2 = 2
        data = [
            tlv8.Entry(TestKeys.KEY_1, 'foo')
        ]
        result = tlv8.encode(data)
        self.assertEqual(b'\x01\x03foo', result)

    def test_encode_int_value(self):
        class TestValues(enum.IntEnum):
            VAL_1 = 1
            VAL_2 = 2

        data = [
            tlv8.Entry(1, TestValues.VAL_2)
        ]
        result = tlv8.encode(data)
        self.assertEqual(b'\x01\x01\x02', result)
