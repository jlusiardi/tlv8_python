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
from struct import pack

import tlv8


class TestTLV8DecodeInteger(unittest.TestCase):
    def test_decode_int1_neg(self):
        input_data = b'\x01\x01' + pack('<b', -123)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, -123),
        ])
        self.assertEqual(expected, result)

    def test_decode_int1_pos(self):
        input_data = b'\x01\x01' + pack('<b', 123)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, 123),
        ])
        self.assertEqual(expected, result)

    def test_decode_int1_un(self):
        input_data = b'\x01\x01' + pack('<B', 123)
        structure = {
            1: tlv8.DataType.UNSIGNED_INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, 123),
        ])
        self.assertEqual(expected, result)

    def test_decode_int2_neg(self):
        input_data = b'\x01\x02' + pack('<h', -12345)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, -12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int2_pos(self):
        input_data = b'\x01\x02' + pack('<h', 12345)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, 12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int2_un(self):
        input_data = b'\x01\x02' + pack('<H', 12345)
        structure = {
            1: tlv8.DataType.UNSIGNED_INTEGER,
        }
        result = tlv8.decode(input_data, structure)
        expected = tlv8.EntryList([
            tlv8.Entry(1, 12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int3_signed(self):
        input_data = b'\x01\x03\x01\x02\x03\x02\x02\x02\x03'
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        self.assertRaises(ValueError, tlv8.decode, input_data, structure)

    def test_decode_int3_unsigned(self):
        input_data = b'\x01\x03\x01\x02\x03\x02\x02\x02\x03'
        structure = {
            1: tlv8.DataType.UNSIGNED_INTEGER,
        }
        self.assertRaises(ValueError, tlv8.decode, input_data, structure)
        # tlv8.decode(input_data, structure)

    def test_decode_int4_neg(self):
        input_data = b'\x01\x04' + pack('<i', -12345)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, -12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int4_pos(self):
        input_data = b'\x01\x04' + pack('<i', 12345)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, 12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int4_un(self):
        input_data = b'\x01\x04' + pack('<I', 12345)
        structure = {
            1: tlv8.DataType.UNSIGNED_INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, 12345),
        ])
        self.assertEqual(expected, result)

    def test_decode_int8_neg(self):
        input_data = b'\x01\x08' + pack('<q', -4611686018427387904)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, -4611686018427387904),
        ])
        self.assertEqual(expected, result)

    def test_decode_int8_pos(self):
        input_data = b'\x01\x08' + pack('<q', 4611686018427387904)
        structure = {
            1: tlv8.DataType.INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, 4611686018427387904),
        ])
        self.assertEqual(expected, result)

    def test_decode_int8_un(self):
        input_data = b'\x01\x08' + pack('<q', 4611686018427387904)
        structure = {
            1: tlv8.DataType.UNSIGNED_INTEGER,
        }
        result = tlv8.decode(input_data, structure)

        expected = tlv8.EntryList([
            tlv8.Entry(1, 4611686018427387904),
        ])
        self.assertEqual(expected, result)
