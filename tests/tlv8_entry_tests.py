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

import tlv8


class TestTLV8Entry(unittest.TestCase):
    def test_str_str(self):
        entry1 = tlv8.Entry(1, 'Hallo')
        self.assertEqual(entry1.__str__(), '<1, Hallo>')

    def test_str_bytes(self):
        entry1 = tlv8.Entry(1, b'23')
        self.assertEqual(entry1.__str__(), '<1, b\'23\'>')

    def test_str_int(self):
        entry1 = tlv8.Entry(1, 23)
        self.assertEqual(entry1.__str__(), '<1, 23>')

    def test_str_float(self):
        entry1 = tlv8.Entry(1, 23.42)
        self.assertEqual(entry1.__str__(), '<1, 23.42>')

    def test_equal_different_types(self):
        entry1 = tlv8.Entry(1, 42)
        self.assertNotEqual(entry1, 'ping')

    def test_equal_different_ids(self):
        entry1 = tlv8.Entry(1, 42)
        entry2 = tlv8.Entry(2, 42)
        self.assertNotEqual(entry1, entry2)

    def test_equal_different_floats(self):
        entry1 = tlv8.Entry(1, 42.1)
        entry2 = tlv8.Entry(1, 42.2)
        self.assertNotEqual(entry1, entry2)

    def test_equal_same_floats(self):
        entry1 = tlv8.Entry(1, 42.1, tlv8.DataType.FLOAT)
        entry2 = tlv8.Entry(1, 42.10001, tlv8.DataType.FLOAT)
        self.assertEqual(entry1, entry2)

    def test_equal(self):
        entry1 = tlv8.Entry(1, 42)
        entry2 = tlv8.Entry(1, 41)
        self.assertFalse(entry1 == entry2)
        self.assertNotEqual(entry1, entry2)

    def test_format_string(self):
        data = [
            tlv8.Entry(1, 3.141),
            tlv8.Entry(2, [
                tlv8.Entry(3, 'hello'),
                tlv8.Entry(4, 'world'),
            ]),
            tlv8.Entry(1, 2)
        ]
        print(tlv8.format_string(data))

    def test_format_string_error_1(self):
        self.assertRaises(ValueError, tlv8.format_string, {})

    def test_format_string_error_2(self):
        self.assertRaises(ValueError, tlv8.format_string, [1])

    def test_create_entry_error(self):
        self.assertRaises(ValueError, tlv8.Entry, 256, b'')
