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


class TestTLV8DeepDecode(unittest.TestCase):
    def test_zero_input(self):
        input_data = b''
        result = tlv8.deep_decode(input_data)
        self.assertEqual(tlv8.EntryList(), result)

    def test_input_to_short_1(self):
        input_data = b'\x01'
        self.assertRaises(ValueError, tlv8.deep_decode, input_data)

    def test_input_to_short_2(self):
        input_data = b'\x01\x01'
        self.assertRaises(ValueError, tlv8.deep_decode, input_data)

    def test_decode_single_entry(self):
        input_data = b'\x02\x01\x23'
        result = tlv8.deep_decode(input_data)
        self.assertEqual(tlv8.EntryList([tlv8.Entry(2, b'\x23')]), result)

    def test_decode_single_entry_bytearry(self):
        input_data = bytearray(b'\x02\x01\x23')
        result = tlv8.deep_decode(input_data)
        self.assertEqual(tlv8.EntryList([tlv8.Entry(2, b'\x23')]), result)

    def test_decode_2_entries(self):
        input_data = b'\x02\x01\x23\x03\x01\x42'
        result = tlv8.deep_decode(input_data)
        self.assertEqual(tlv8.EntryList([tlv8.Entry(2, b'\x23'), tlv8.Entry(3, b'\x42')]), result)

    def test_decode_4(self):
        input_data = b'\x01\x01\x23\x02\x03\x04\x01\x42\x01\x01\x23'
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'#'),
            tlv8.Entry(2, tlv8.EntryList([
                tlv8.Entry(4, b'B'),
            ])),
            tlv8.Entry(1, b'#'),
        ])
        self.assertEqual(expected, result)

    def test_decode_float(self):
        input_data = b'\x01\x04' + pack('<f', 3.141)
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'%\x06I@'),
        ])
        self.assertEqual(expected, result)

    def test_decode_int1(self):
        input_data = b'\x01\x01' + pack('<b', -123)
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'\x85'),
        ])
        self.assertEqual(expected, result)

    def test_decode_int2(self):
        input_data = b'\x01\x02' + pack('<h', 12345)
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'90'),
        ])
        self.assertEqual(expected, result)

    def test_decode_int3(self):
        input_data = b'\x01\x03' + pack('<i', 12345)
        self.assertRaises(ValueError, tlv8.deep_decode, input_data)

    def test_decode_int4(self):
        input_data = b'\x01\x08' + pack('<q', 4611686018427387904)
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'\x00\x00\x00\x00\x00\x00\x00@'),
        ])
        self.assertEqual(expected, result)

    def test_decode_int8(self):
        input_data = b'\x01\x04' + pack('<i', 12345)
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'90\x00\x00'),
        ])
        self.assertEqual(expected, result)

    def test_decode_example_2(self):
        input_data = b'\x01\x01\x00'
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, b'\x00'),
        ])
        self.assertEqual(expected, result)

    def test_decode_example_3(self):
        input_data = b'\x01\x15\x01\x10e\xad\x8b\xe8\xb3fD\xcb\xbde#\xccc\n\xb8\xef\x02\x01\x01'
        result = tlv8.deep_decode(input_data)
        expected = tlv8.EntryList([
            tlv8.Entry(1, tlv8.EntryList([
                tlv8.Entry(1, b'e\xad\x8b\xe8\xb3fD\xcb\xbde#\xccc\n\xb8\xef'),
                tlv8.Entry(2, b'\x01'),
            ])),
        ])
        self.assertEqual(expected, result)

    def test_decode_257bytes(self):
        data = b''
        for i in range(0, 257):
            data += pack('<B', i % 256)

        input_data = b'\x17\xff' + data[0:255] + b'\x17\x02' + data[255:]

        result = tlv8.deep_decode(input_data)

        expected = tlv8.EntryList([
            tlv8.Entry(23, data)
        ])
        self.assertEqual(result, expected)

    def test_decode_supported_rtp_configs(self):
        data = \
            b'\x02\x01\x00' + \
            b'\x00\x00' + \
            b'\x02\x01\x01'
        result = tlv8.deep_decode(data, )
        expected_data = tlv8.EntryList([
            tlv8.Entry(2, b'\x00'),
            tlv8.Entry(0, tlv8.EntryList()),
            tlv8.Entry(2, b'\x01')
        ])
        self.assertEqual(result, expected_data)

    def test_encode_supported_video_stream_configuration(self):
        data = \
            b'\x01\x30' \
                b'\x01\x01\x00' \
                b'\x02\x0f' \
                    b'\x01\x01\x00' \
                    b'\x02\x01\x00' \
                    b'\x03\x01\x00' \
                    b'\x04\x01\x01' \
                    b'\x05\x01\n' \
                b'\x03\x0b' \
                    b'\x01\x02\x00\x05' \
                    b'\x02\x02 \x03' \
                    b'\x03\x01\x1e' \
                b'\xff\x00' \
                b'\x03\x0b' \
                    b'\x01\x02\x80\x02' \
                    b'\x02\x02\xe0\x01' \
                    b'\x03\x01\x1e' \
            b'\xff\x00' \
            b'\x01\x2d' \
                b'\x01\x01\x00' \
                b'\x02\x0c' \
                    b'\x01\x01\x00' \
                    b'\x02\x01\x00' \
                    b'\x03\x01\x00' \
                    b'\x04\x01\x00' \
                b'\x03\x0b' \
                    b'\x01\x02\x00\x05' \
                    b'\x02\x02 \x03' \
                    b'\x03\x01\x1e' \
                b'\xff\x00' \
                b'\x03\x0b' \
                    b'\x01\x02\x80\x02' \
                    b'\x02\x02\xe0\x01' \
                    b'\x03\x01\x1e'
        result = tlv8.deep_decode(data)
        expected_data = tlv8.EntryList([
            tlv8.Entry(1, tlv8.EntryList([  # video codec config
                tlv8.Entry(1, b'\x00'),  # h.264
                tlv8.Entry(2, tlv8.EntryList([  # video codec param
                    tlv8.Entry(1, b'\x00'),  # Constrained Baseline Profile
                    tlv8.Entry(2, b'\x00'),  # Level 3.1
                    tlv8.Entry(3, b'\x00'),  # Packetization mode: Non-interleaved mode
                    tlv8.Entry(4, b'\x01'),  # CVO not enabled
                    tlv8.Entry(5, b'\n'),  # CVO ID
                ])),
                tlv8.Entry(3, tlv8.EntryList([  # video attributes
                    tlv8.Entry(1, b'\x00\x05'),  # width
                    tlv8.Entry(2, b' \x03'),  # height
                    tlv8.Entry(3, b'\x1e')  # fps
                ])),
                tlv8.Entry(255, tlv8.EntryList()),
                tlv8.Entry(3, tlv8.EntryList([  # video attributes
                    tlv8.Entry(1, b'\x80\x02'),  # width
                    tlv8.Entry(2, b'\xe0\x01'),  # height
                    tlv8.Entry(3, b'\x1e')  # fps
                ]))
            ])),
            tlv8.Entry(255, tlv8.EntryList()),
            tlv8.Entry(1, tlv8.EntryList([
                tlv8.Entry(1, b'\x00'),  # h.264
                tlv8.Entry(2, tlv8.EntryList([  # video codec param
                    tlv8.Entry(1, b'\x00'),  # Constrained Baseline Profile
                    tlv8.Entry(2, b'\x00'),  # Level 3.1
                    tlv8.Entry(3, b'\x00'),  # Packetization mode: Non-interleaved mode
                    tlv8.Entry(4, b'\x00'),  # CVO not enabled
                ])),
                tlv8.Entry(3, tlv8.EntryList([  # video attributes
                    tlv8.Entry(1, b'\x00\x05'),  # width
                    tlv8.Entry(2, b' \x03'),  # height
                    tlv8.Entry(3, b'\x1e')  # fps
                ])),
                tlv8.Entry(255, tlv8.EntryList()),
                tlv8.Entry(3, tlv8.EntryList([  # video attributes
                   tlv8.Entry(1, b'\x80\x02'),  # width
                   tlv8.Entry(2, b'\xe0\x01'),  # height
                   tlv8.Entry(3, b'\x1e')  # fps
                ]))
            ]))
        ])

        self.assertEqual(result, expected_data)

    def test_decode_error_1(self):
        self.assertRaises(ValueError, tlv8.deep_decode, {})

    def test_decode_missing_separator_strict(self):
        data = b'\x01\x01\x02\x01\x01\x02'
        self.assertRaises(ValueError, tlv8.deep_decode, data, strict_mode=True)

    def test_decode_missing_separator_nonstrict(self):
        data = b'\x01\x01\x02\x01\x01\x02'
        result = tlv8.deep_decode(data, strict_mode=False)
        self.assertEqual(result, tlv8.EntryList([tlv8.Entry(1, b'\x02'), tlv8.Entry(1, b'\x02')]))

    def test_decode_error_4(self):
        data = b'\x01\x02Hi'
        result = tlv8.deep_decode(data)
        expected_data = tlv8.EntryList([
            tlv8.Entry(1, b'Hi')
        ])
        self.assertEqual(result, expected_data)
