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


class TestTLV8(unittest.TestCase):
    def test_bytes_0length_bytes(self):
        entry = tlv8.Entry(23, b'', tlv8.DataType.BYTES)
        self.assertEqual(entry.encode(), b'\x17\x00')

    def test_bytes_0length_string(self):
        entry = tlv8.Entry(23, '', tlv8.DataType.STRING)
        self.assertEqual(entry.encode(), b'\x17\x00')

    def test_bytes_0length_autodetect(self):
        entry = tlv8.Entry(23, b'')
        self.assertEqual(entry.encode(), b'\x17\x00')

    def test_bytes_10bytes(self):
        entry = tlv8.Entry(23, b'0123456789', tlv8.DataType.BYTES)
        self.assertEqual(entry.encode(), b'\x17\x0a0123456789')

    def test_bytes_256bytes(self):
        data = b''
        for i in range(0, 256):
            data += pack('<B', i)
        entry = tlv8.Entry(23, data, tlv8.DataType.BYTES)
        expected_data = b'\x17\xff' + data[0:255] + b'\x17\x01' + data[255:]
        self.assertEqual(entry.encode(), expected_data)

    def test_bytes_257bytes(self):
        data = b''
        for i in range(0, 257):
            data += pack('<B', i % 256)
        entry = tlv8.Entry(23, data, tlv8.DataType.BYTES)
        expected_data = b'\x17\xff' + data[0:255] + b'\x17\x02' + data[255:]
        self.assertEqual(entry.encode(), expected_data)

    def test_string_0bytes(self):
        entry = tlv8.Entry(23, '', tlv8.DataType.STRING)
        self.assertEqual(entry.encode(), b'\x17\x00')

    def test_string_hello(self):
        entry = tlv8.Entry(23, 'hello', tlv8.DataType.STRING)
        self.assertEqual(entry.encode(), b'\x17\x05hello')

    def test_string_world(self):
        entry = tlv8.Entry(23, '🌍', tlv8.DataType.STRING)
        self.assertEqual(entry.encode(), b'\x17\x04\xf0\x9f\x8c\x8d')

    def test_float(self):
        entry = tlv8.Entry(23, 3.141, tlv8.DataType.FLOAT)
        self.assertEqual(entry.encode(), b'\x17\x04%\x06I@')

    def test_int_auto_length(self):
        entry = tlv8.Entry(23, 1, tlv8.DataType.INTEGER)
        self.assertEqual(entry.encode(), b'\x17\x01\x01')

    def test_int_overwrite_length(self):
        entry = tlv8.Entry(23, 1, tlv8.DataType.INTEGER, length=8)
        self.assertEqual(entry.encode(), b'\x17\x08\x01\x00\x00\x00\x00\x00\x00\x00')

    def test_unsigned_int_auto_length(self):
        entry = tlv8.Entry(23, 1, tlv8.DataType.UNSIGNED_INTEGER)
        self.assertEqual(entry.encode(), b'\x17\x01\x01')

    def test_unsigned_int_overwrite_length(self):
        entry = tlv8.Entry(23, 1, tlv8.DataType.UNSIGNED_INTEGER, length=8)
        self.assertEqual(entry.encode(), b'\x17\x08\x01\x00\x00\x00\x00\x00\x00\x00')

    def test_encode_different(self):
        data = [
            tlv8.Entry(23, b'23', tlv8.DataType.BYTES),
            tlv8.Entry(22, '23', tlv8.DataType.STRING)
        ]
        result = tlv8.encode(data)
        expected_data = data[0].encode() + data[1].encode()
        self.assertEqual(result, expected_data)

    def test_encode_same_autodetect(self):
        structure = [
            tlv8.Entry(1, 23),
            tlv8.Entry(2, 2345)
        ]
        result = tlv8.encode(structure)
        expected_data = b'\x01\x01\x17\x02\x02)\t'
        self.assertEqual(result, expected_data)

    def test_encode_same(self):
        data = [
            tlv8.Entry(23, b'23', tlv8.DataType.BYTES),
            tlv8.Entry(23, '23', tlv8.DataType.STRING)
        ]
        result = tlv8.encode(data)
        expected_data = data[0].encode() + b'\xff\x00' + data[1].encode()
        self.assertEqual(result, expected_data)

    def test_encode_same_set_sep_type(self):
        data = [
            tlv8.Entry(23, b'23', tlv8.DataType.BYTES),
            tlv8.Entry(23, '23', tlv8.DataType.STRING)
        ]
        result = tlv8.encode(data, 0)
        expected_data = data[0].encode() + b'\x00\x00' + data[1].encode()
        self.assertEqual(result, expected_data)

    def test_encode_same_set_sep_type_occurs(self):
        data = [
            tlv8.Entry(23, '42'),
            tlv8.Entry(23, '43')
        ]
        with self.assertRaises(ValueError) as error_context:
            tlv8.encode(data, 23)
        self.assertEqual(str(error_context.exception), 'Separator type id 23 occurs with list of entries!')

    def test_encode_3same(self):
        data = [
            tlv8.Entry(23, b'23', tlv8.DataType.BYTES),
            tlv8.Entry(23, '23', tlv8.DataType.STRING),
            tlv8.Entry(23, '23', tlv8.DataType.STRING)
        ]
        result = tlv8.encode(data)
        expected_data = \
            data[0].encode() + b'\xff\x00' + \
            data[1].encode() + b'\xff\x00' + \
            data[2].encode()
        self.assertEqual(result, expected_data)

    def test_encode_supported_rtp_configs(self):
        data = [
            tlv8.Entry(2, 0),
            tlv8.Entry(2, 1)
        ]
        result = tlv8.encode(data, separator_type_id=0x00)
        expected_data = \
            b'\x02\x01\x00' + \
            b'\x00\x00' + \
            b'\x02\x01\x01'
        self.assertEqual(result, expected_data)

    def test_encode_supported_video_stream_configuration(self):
        data = [
            tlv8.Entry(1, [  # video codec config
                tlv8.Entry(1, 0),  # h.264
                tlv8.Entry(2, [  # video codec param
                    tlv8.Entry(1, 0),  # Constrained Baseline Profile
                    tlv8.Entry(2, 0),  # Level 3.1
                    tlv8.Entry(3, 0),  # Packetization mode: Non-interleaved mode
                    tlv8.Entry(4, 1),  # CVO not enabled
                    tlv8.Entry(5, 10),  # CVO ID
                ]),
                tlv8.Entry(3, [  # video attributes
                    tlv8.Entry(1, 1280),  # width
                    tlv8.Entry(2, 800),  # height
                    tlv8.Entry(3, 30)  # fps
                ]),
                tlv8.Entry(3, [  # video attributes
                    tlv8.Entry(1, 640),  # width
                    tlv8.Entry(2, 480),  # height
                    tlv8.Entry(3, 30)  # fps
                ])
            ]),
            tlv8.Entry(1, [
                tlv8.Entry(1, 0),  # h.264
                tlv8.Entry(2, [  # video codec param
                    tlv8.Entry(1, 0),  # Constrained Baseline Profile
                    tlv8.Entry(2, 0),  # Level 3.1
                    tlv8.Entry(3, 0),  # Packetization mode: Non-interleaved mode
                    tlv8.Entry(4, 0),  # CVO not enabled
                ]),
                tlv8.Entry(3, [  # video attributes
                    tlv8.Entry(1, 1280),  # width
                    tlv8.Entry(2, 800),  # height
                    tlv8.Entry(3, 30)  # fps
                ]),
                tlv8.Entry(3, [  # video attributes
                    tlv8.Entry(1, 640),  # width
                    tlv8.Entry(2, 480),  # height
                    tlv8.Entry(3, 30)  # fps
                ])
            ])
        ]
        result = tlv8.encode(data)
        expected_data = \
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
        self.assertEqual(result, expected_data)

    def test_autodetection_of_types(self):
        data = [
            tlv8.Entry(1, 3.141),
            tlv8.Entry(2, [
                tlv8.Entry(3, 'hello'),
                tlv8.Entry(4, 'world')
            ]),
            tlv8.Entry(1, 2)
        ]
        result = tlv8.encode(data)
        expected_data = b'\x01\x04%\x06I@\x02\x0e\x03\x05hello\x04\x05world\x01\x01\x02'
        self.assertEqual(result, expected_data)

    def test_encode_error_1(self):
        self.assertRaises(ValueError, tlv8.encode, {})

    def test_encode_error_2(self):
        self.assertRaises(ValueError, tlv8.encode, [1])

    def test_encode_128bit_int(self):
        self.assertRaises(ValueError, tlv8.encode,
                          [tlv8.Entry(1, 85070591730234615865843651857942052864, tlv8.DataType.UNSIGNED_INTEGER)])

    def test_encode_128bit_signed_int(self):
        self.assertRaises(ValueError, tlv8.encode,
                          [tlv8.Entry(1, -85070591730234615865843651857942052864, tlv8.DataType.INTEGER)])

    def test_encode_64bit_int(self):
        result = tlv8.encode([tlv8.Entry(1, 4611686018427387904)])
        self.assertEqual(b'\x01\x08\x00\x00\x00\x00\x00\x00\x00@', result)

    def test_encode_32bit_int(self):
        result = tlv8.encode([tlv8.Entry(1, 1073741824)])
        self.assertEqual(b'\x01\x04\x00\x00\x00@', result)

    def test_encode_16bit_int(self):
        result = tlv8.encode([tlv8.Entry(1, 16384)])
        self.assertEqual(b'\x01\x02\x00@', result)

    def test_encode_8bit_signed_int(self):
        result = tlv8.encode([tlv8.Entry(1, -64, tlv8.DataType.INTEGER)])
        self.assertEqual(b'\x01\x01\xc0', result)

    def test_encode_8bit_unsigned_int(self):
        result = tlv8.encode([tlv8.Entry(1, 64, tlv8.DataType.UNSIGNED_INTEGER)])
        self.assertEqual(b'\x01\x01@', result)

    def test_encode_non_encodable(self):
        self.assertRaises(ValueError, tlv8.encode, [tlv8.Entry(1, {1: 2})])

    def test_encode_bytearray_autodetect(self):
        result = tlv8.encode([tlv8.Entry(1, bytearray(b'\x01'))])
        self.assertEqual(b'\x01\x01\x01', result)

    def test_encode_bytearray(self):
        result = tlv8.encode([tlv8.Entry(1, bytearray(b'\x01'), tlv8.DataType.BYTES)])
        self.assertEqual(b'\x01\x01\x01', result)
