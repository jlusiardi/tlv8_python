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
import binascii

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

    def test_3(self):
        """
        Example for a broken decode from https://github.com/jlusiardi/homekit_python/issues/194.
        """
        data = '01ff0601040440371bf8c6cd6a7fb85e77a7b436a1b5300ed2023ca7e23f61303856a57358fd8ac03f288472776854765eb3' \
               'a2fcb4497c8b5497c29c88a574479030ec36b176ae05ff85c337879f0a4146a9cc089e0cb48ba3c9c21af0b206d493b224de' \
               'ee52ff0f9b1d8710db6531748ee6d1d66b8b4a6d0690670fb8f1233010d190c4ede1776cb10806eae66c78881647e82e9ba7' \
               'c806f52184c6f108275719cf425c4f8ea0e86c6534712343f88a1482c986e3dd252715872dee506520903c17d27f02ea8957' \
               '719c255631b78a9f2ecb7af0dc245b370cefef28f4652eebbe34afda0138039714665dd880559d1f2667294207892137820c' \
               'd80533d8c0b22601ffa49d1bdc1b641a33297fe59672a89d69391417c77e31283cd7f0d40920004d1bf1fc38357d9599ac2b' \
               '4d8ce3ac7ab8725a01500d198e94b00da80aac64ead393b266dcf9d4a07c05ff34548f7ebebd63f8a00ae2c82f6ee8ac6bcc' \
               'e0ab1030e9268c36714e2ec11c3bf21331129d62978e069dd087cbbdc31bdd6e0cf4ca825b91ab3c8b240de19aa097fc01cd' \
               '471e8c1b5598044d21be12b84c97a1d70e46681e5ecebbde1c33bae9bbd9b3ad41ba2aff8f1f952d0ef0cfcb8a674d5b4c7f' \
               '515ba94341334e86aac277920bd9080b9bf702e16671a3e41c0930beb8a552aefc28a3a9a7f2818e8fbb84c37ae10fb6c5d2' \
               '2e6ba9899e01f082381c9a3344ecbaf801ff85e33306ec9823e72ec4c93f9a45aa657b16f46757aaaf7c74daf35840e68749' \
               '42c132f4a639562920318b9f9867d8e5b0d50deac48c4e14842c91d565b0dd1fec667d092d123a4e1a05fff0b7070f184b4f' \
               '399532c0d1cc0aaea326efea765bc88ace048040a3e07a741e26ef55203bb3f76c075e3b6d20ede89a2eaa63e23376b0dff4' \
               'ef3a797df34a39d8130f60316e86cafcb264b0b570376ba911dc2bda031328ea1c915a724bc69ad2700623ed19c3ae75f946' \
               '4e3b1669adb916ad58e3252580911db2b535af3f2b2207aea880a0d24f1f759888bd5e25b6cf7b2e5ce825ab0fd943a8378a' \
               'eb12906e0965540af14dc0bfa3fae2eb5361992efaf56501ff6ed5c6e686a4af3c2fa121c810cb84cd5abac94f6d618af493' \
               '29e34fa613d2b758e3bc79eb03cb78328f9cd34df43566589615e42088681b4f69775350c9abf68c107d312b0f2421bb53cf' \
               '05ff50c14d6ff0da74b50d9b080c5c06175d66b24b35eb1e25f940170c0815a0ead23703b86da2103cd1b33021fd981d95c6' \
               'a32a3752dc903b0acba949d7d51a1bcabaebc52941bb25d558132feb1794481c0a5911e53553407a8771503d7673d4c3061a' \
               '4d2d41a2897fe507423509760fbe4847423a51155b99b67bf43c72958ce9409a459b5ce42e61309e96091411b256ec294fb0' \
               'f32782efc80d9d548f3cee4fdb21babd011e118238ec7545b24e5af74317a2670179930156512875653dce4e957e94a7596f' \
               'a7e2b533a3eacb9781634c79c094e2cbfcfc62128a25431f9b56cc40b6097614e7a4b08c32b3a7f2e471f55a295a9a06e5b0' \
               'e07dec2ad282842aa6f176052acd544cb5d67c206a3e38e80e32f560a57edda173892a39b021d616d8f2862a5d111e6610c1e7'
        data = binascii.unhexlify(data)
        resp_data = tlv8.decode(data, {1: tlv8.DataType.BYTES})
        self.assertIsNotNone(resp_data.first_by_id(1))
        self.assertEqual(len(resp_data.first_by_id(1).data), 510)

        resp_data = tlv8.decode(resp_data.first_by_id(1).data, {4: tlv8.DataType.BYTES, 6: tlv8.DataType.BYTES})
        self.assertIsNotNone(resp_data.first_by_id(4))
        print(resp_data.first_by_id(4).data)
        self.assertEqual(resp_data.first_by_id(4).data,
                         b'7\x1b\xf8\xc6\xcdj\x7f\xb8^w\xa7\xb46\xa1\xb50\x0e\xd2\x02<\xa7\xe2?a08V\xa5sX\xfd\x8a'
                         b'\xc0?(\x84rwhTv^\xb3\xa2\xfc\xb4I|\x8bT\x97\xc2\x9c\x88\xa5tG\x900\xec6\xb1v\xae')
        self.assertIsNotNone(resp_data.first_by_id(6))
        self.assertEqual(resp_data.first_by_id(6).data, b'\x04')
