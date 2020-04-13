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
import json

import tlv8


class TestTLV8ToJson(unittest.TestCase):
    def test_entry_to_json(self):
        e = tlv8.Entry(1, 'hello')
        j = json.dumps(e, cls=tlv8.JsonEncoder)
        self.assertEqual('{"1": "hello"}', j)

    def test_entry_list_to_json(self):
        e1 = tlv8.Entry(1, 'hello')
        e2 = tlv8.Entry(2, 'world')
        el = tlv8.EntryList([e1, e2])
        j = json.dumps(el, cls=tlv8.JsonEncoder)
        self.assertEqual('[{"1": "hello"}, {"2": "world"}]', j)

    def test_string_to_json(self):
        j = json.dumps(True, cls=tlv8.JsonEncoder)
        self.assertEqual('true', j)
