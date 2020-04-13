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


class TestTLV8RealWorld(unittest.TestCase):
    def test_1(self):
        data = tlv8.EntryList([
            tlv8.Entry(1, b'W\x1ah\xac)\x04C\xfd\x84\xb36\t\xd1\x1bO\x83'),
            tlv8.Entry(3, tlv8.EntryList([
                tlv8.Entry(1, 0),
                tlv8.Entry(2, '192.168.178.222'),
            ]))
        ])
        encoded = tlv8.encode(data)
        decoded = tlv8.decode(
            encoded,
            {
                1: tlv8.DataType.BYTES,
                3: {
                    1: tlv8.DataType.UNSIGNED_INTEGER,
                    2: tlv8.DataType.STRING
                }
            }
        )
        self.assertEqual(data, decoded)
        encoded_2 = tlv8.encode(decoded)
        self.assertEqual(encoded, encoded_2)

    def test_2(self):
        class Foo(enum.IntEnum):
            Bar = 1
            Baz = 2

        data = tlv8.EntryList([
            tlv8.Entry(1, b'W\x1ah\xac)\x04C\xfd\x84\xb36\t\xd1\x1bO\x83'),
            tlv8.Entry(3, tlv8.EntryList([
                tlv8.Entry(1, Foo.Bar),
                tlv8.Entry(2, '192.168.178.222'),
            ]))
        ])
        encoded = tlv8.encode(data)
        decoded = tlv8.decode(
            encoded,
            {
                1: tlv8.DataType.BYTES,
                3: {
                    1: Foo,
                    2: tlv8.DataType.STRING
                }
            }
        )
        self.assertEqual(data, decoded)
        encoded_2 = tlv8.encode(decoded)
        self.assertEqual(encoded, encoded_2)
