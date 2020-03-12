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

__all__ = [
    'TestTLV8', 'TestTLV8Decode', 'TestTLV8Entry', 'TestTLV8Enum', 'TestTLV8EntryList'
]

from tests.tlv8_encode_tests import TestTLV8
from tests.tlv8_decode_tests import TestTLV8Decode
from tests.tlv8_deep_decode_tests import TestTLV8DeepDecode
from tests.tlv8_entry_tests import TestTLV8Entry
from tests.tlv8_enum_test import TestTLV8Enum
from tests.tlv8_entrylist_tests import TestTLV8EntryList
