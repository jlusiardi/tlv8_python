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


class TestTLV8EntryList(unittest.TestCase):
    def test_entrylist_init(self):
        with self.assertRaises(ValueError) as error_context:
            tlv8.EntryList('not a list')
        self.assertEqual(str(error_context.exception), 'No valid list: not a list')

        with self.assertRaises(ValueError) as error_context:
            tlv8.EntryList(['not an entry'])
        self.assertEqual(str(error_context.exception), 'Not a valid tlv8.Entry: not an entry')

    def test_entrylist_append(self):
        el = tlv8.EntryList()
        with self.assertRaises(ValueError) as error_context:
            el.append('not a list')
        self.assertEqual(str(error_context.exception), 'Not an tlv8.Entry: not a list')

    def test_entrylist_compare_empty(self):
        el_1 = tlv8.EntryList()
        el_2 = tlv8.EntryList()
        self.assertEqual(el_1, el_2)

    def test_entrylist_compare_not_a_list(self):
        el_1 = tlv8.EntryList()
        self.assertNotEqual(el_1, 'not a entry list')

    def test_entrylist_compare_1_equal(self):
        el_1 = tlv8.EntryList([tlv8.Entry(1, 2)])
        el_2 = tlv8.EntryList([tlv8.Entry(1, 2)])
        self.assertEqual(el_1, el_2)

    def test_entrylist_compare_1_not_equal(self):
        el_1 = tlv8.EntryList([tlv8.Entry(1, 2)])
        el_2 = tlv8.EntryList([tlv8.Entry(1, 3)])
        self.assertNotEqual(el_1, el_2)

    def test_entrylist_length(self):
        el = tlv8.EntryList()
        self.assertEqual(0, len(el))
        el.append(tlv8.Entry(1, 2))
        self.assertEqual(1, len(el))
        el.append(tlv8.Entry(1, 2))
        self.assertEqual(2, len(el))

    def test_entrylist_index(self):
        el = tlv8.EntryList()
        e1 = tlv8.Entry(1, 2)
        e2 = tlv8.Entry(3, 4)
        el.append(e1)
        el.append(e2)
        self.assertEqual(e2, el[1])

    def test_entrylist_decode(self):
        input_data = bytearray(b'\x02\x01\x23')
        result = tlv8.decode(input_data)
        self.assertIsInstance(result, tlv8.EntryList)
        self.assertEqual(result, tlv8.EntryList([tlv8.Entry(2, b'\x23')]))

    def test_entrylist_encode(self):
        el = tlv8.EntryList([tlv8.Entry(2, b'\x23')])
        result = el.encode()
        self.assertEqual(b'\x02\x01\x23', result)

    def test_entrylist_encode_same_sep_type(self):
        el = tlv8.EntryList([
            tlv8.Entry(2, b'\x23'),
            tlv8.Entry(2, b'\x42')
        ])
        result = el.encode(1)
        self.assertEqual(b'\x02\x01\x23\x01\x00\x02\x01\x42', result)

    def test_entrylist_assert_has(self):
        el = tlv8.EntryList([
            tlv8.Entry(2, b'\x23')
        ])
        with self.assertRaises(AssertionError) as error_context:
            el.assert_has(3, 'no bla bla')
        self.assertEqual(str(error_context.exception), 'no bla bla')

        el.assert_has(2, 'no bla bla')

    def test_entrylist_decode_nested(self):
        data = b'\x01\x04%\x06I@\x02\x0e\x03\x05hello\x04\x05world\x03\x01\x02'
        result = tlv8.decode(data, {
            1: tlv8.DataType.FLOAT,
            2: {
                3: tlv8.DataType.STRING,
                4: tlv8.DataType.STRING,
            },
            3: tlv8.DataType.INTEGER
        })
        self.assertIsInstance(result, tlv8.EntryList)
        self.assertIsInstance(result[1].data, tlv8.EntryList)

    def test_entrylist_by_id(self):
        el = tlv8.EntryList([
            tlv8.Entry(2, b'\x23'),
            tlv8.Entry(2, b'\x42')
        ])
        self.assertEqual(el.by_id(1), tlv8.EntryList())
        self.assertEqual(el.by_id(2), el)

    def test_entrylist_first_by_id(self):
        el = tlv8.EntryList([
            tlv8.Entry(2, b'\x23'),
            tlv8.Entry(2, b'\x42')
        ])
        self.assertEqual(el.first_by_id(1), None)
        self.assertEqual(el.first_by_id(2), el[0])

    def test_entrylist_format_string(self):
        el = tlv8.EntryList([
            tlv8.Entry(1, 1),
            tlv8.Entry(2, tlv8.EntryList([
                tlv8.Entry(4, 4),
                tlv8.Entry(5, 5)
            ])),
            tlv8.Entry(3, 3),
        ])
        result = tlv8.format_string(el)
        expected = """[
  <1, 1>,
  <2, [
    <4, 4>,
    <5, 5>,
  ]>,
  <3, 3>,
]"""
        self.assertEqual(result, expected)
