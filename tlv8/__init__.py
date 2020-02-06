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
    'encode', 'format_string', 'decode', 'DataType', 'Entry'
]

from enum import IntEnum
from struct import pack, unpack, error

try:
    from math import isclose
except ImportError:
    def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
        return abs(a - b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)


def format_string(entries: list, indent=0) -> str:
    """
    Format a list of TLV8 Entry objects as str instance. The hierarchy of the entries will be represented by
    increasing the indentation of the output.

    Example:
    ```
        data = [
            tlv8.Entry(1, 3.141),
            tlv8.Entry(2, [
                tlv8.Entry(3, 'hello'),
                tlv8.Entry(4, 'world'),
            ]),
            tlv8.Entry(1, 2)
        ]
        print(tlv8.format_string(data))
    ```
    will become:
    ```
        [
          <1, 3.141>,
          <2, [
            <3, hello>,
            <4, world>,
          ]>,
          <1, 2>,
        ]
    ```

    :param entries: a list of tlv8.Entries objects
    :param indent: the level of indentation to be used
    :return: a str instance with the formatted representation of the input
    :raises ValueError: if the input parameter is not conform to a list of tlv8.Entry objects
    """
    if not isinstance(entries, list):
        raise ValueError('The parameter entries must be of type list')
    result = '[\n'
    for entry in entries:
        if not isinstance(entry, Entry):
            raise ValueError('The parameter entries must only contain elements of type tlv8.Entry')
        result += ' ' * (indent + 2) + entry.format_string(indent + 2) + '\n'
    result += ' ' * indent + ']'
    return result


def encode(entries: list, separator_type_id=0xff) -> bytes:
    """
    Function to encode a list of TLV Entry objects into a sequence of bytes following the rules for creating TLVs.

    :param entries: a list of tlv8.Entries objects
    :param separator_type_id: the 8-bit id of the separator to be used in two fields of the same type id are directly
        after one another in the list. The default is (as defined in table 5-6, page 51 of HomeKit Accessory Protocol
        Specification Non-Commercial Version Release R2) 0xff.
    :return: an instance of bytes. if nothing was encoded, it returns an empty instance
    :raises ValueError: if the input parameter is not conform to a list of tlv8.Entry objects
    """
    if not isinstance(entries, list):
        raise ValueError('The parameter entries must be of type list')
    result = b''
    last_type_id = None
    for entry in entries:
        if not isinstance(entry, Entry):
            raise ValueError('The parameter entries must only contain elements of type tlv8.Entry')
        if last_type_id == entry.type_id:
            # must insert separator of two entries of the same type succeed one an other
            result += pack('<B', separator_type_id) + b'\x00'
        result += entry.encode()
        last_type_id = entry.type_id
    return result


def decode(data: bytes, expected=None, strict_mode=False) -> list:
    """
    Decodes a sequence of bytes into a list of hierarchical TLV8 Entries.

    :param data: a bytes instance.
    :param expected: a dict of type ids onto expected DataTypes. If an entry is again a TLV8 Entry, use another dict to
         describe the hierarchical structure. This defaults to None which means not filtering will be performed but
         also no interpretation of the entries is done. This means they will be returned bytes sequence.
    :param strict_mode: if set to True, bail out if there consecutive entry of the same type without separators.
    :return: a list of tlv8.Entry objects
    :raises: ValueError on failures during decoding
    """
    if not isinstance(data, bytes):
        raise ValueError('data parameter must be bytes')
    if len(data) == 0:
        # no data, nothing to do
        return []
    tmp = []
    remaining_data = data
    while len(remaining_data) > 0:
        if len(remaining_data) < 2:
            # the shortest encoded TLV8 is 3 bytes, we got less, so raise an error
            raise ValueError('Bytes with length {len} is not a valid TLV8.'.format(len=len(data)))

        tlv_id = unpack('<B', remaining_data[0:1])[0]
        tlv_len = unpack('<B', remaining_data[1:2])[0]
        if len(remaining_data[2:]) < tlv_len:
            # the remaining data is less than the encoded length
            raise ValueError('Not enough data left.')
        tlv_data = remaining_data[2:2 + tlv_len]
        if len(tmp) > 0 and tmp[-1].type_id == tlv_id:
            # we have the same type id so we expect the size of the data so far to be 0 mod 255
            if len(tmp[-1].data) % 255 != 0:
                # it there was no max size fragment before, this is either
                if strict_mode:
                    # an error in strict mode
                    raise ValueError('Missing separator detected.')
                else:
                    # or we let it pass as a second instance of the type id. both could be wrong
                    tmp.append(Entry(tlv_id, tlv_data))
            else:
                # max size fragments are added the new data
                tmp[-1].data += tlv_data
        else:
            tmp.append(Entry(tlv_id, tlv_data))
        remaining_data = remaining_data[2 + tlv_len:]

    # if we do not know what is expected, we just return the unfiltered, uninterpreted but parsed list of entries
    if not expected:
        return tmp

    result = []
    for entry in tmp:
        if entry.type_id in expected:
            expected_data_type = expected[entry.type_id]
            entry.data_type = expected_data_type
            tlv_len = len(entry.data)
            if expected_data_type == DataType.INTEGER:
                if tlv_len == 1:
                    entry.data = unpack('<b', entry.data)[0]
                elif tlv_len == 2:
                    entry.data = unpack('<h', entry.data)[0]
                elif tlv_len == 4:
                    entry.data = unpack('<i', entry.data)[0]
                elif tlv_len == 8:
                    entry.data = unpack('<q', entry.data)[0]
                else:
                    raise ValueError('Integer of unknown length: {len}'.format(len=tlv_len))
            if expected_data_type == DataType.FLOAT:
                entry.data = unpack('<f', entry.data)[0]
            if expected_data_type == DataType.STRING:
                entry.data = entry.data.decode()
            if type(expected_data_type) == dict:
                entry.data = decode(entry.data, expected_data_type)
            result.append(entry)

    return result


class DataType(IntEnum):
    """
    The various types of data that can be used in the tlv8 context.
    """
    BYTES = 1
    TLV8 = 2
    INTEGER = 3
    FLOAT = 4
    STRING = 5
    AUTODETECT = 6  # only during encoding


class Entry:
    def __init__(self,
                 type_id: int,
                 data,
                 data_type: DataType = DataType.AUTODETECT,
                 length=-1):
        """
        Create an tlv8 entry instance.

        :param type_id: the type id of the entry. Must be between 0 and 255 (8-bit type id)
        :param data: the data to be stored in this entry.
        :param data_type: the data type of the entry. Defaults to DataType.AUTODETECT.
        :param length: if set, this overrides the automatic length detection. This
            used for integer, when there is special need to set higher byte
            count than the value would need.
        :raises: ValueError if the type_id is not within the 8-bit range.
        """
        if type_id < 0 or 255 < type_id:
            raise ValueError('The type_id parameter must between 0 and 255 but is {val}'.format(val=type_id))
        self.type_id = type_id
        self.data_type = data_type
        self.data = data
        self.length = length

    def __eq__(self, other):
        """
        Check for equality of 2 TLV8 entries. If the data type of an entry is float, it uses `isclose` to compare for
        an equality of floats for a precision of 1e-06.

        :param other: the other instance to compare to
        :return: True if the entries are equal, False if not
        """
        if isinstance(other, self.__class__):
            if self.type_id != other.type_id:
                return False
            # floats are difficult to check for exact equality...
            if self.data_type == DataType.FLOAT or other.data_type == DataType.FLOAT:
                return isclose(self.data, other.data, rel_tol=1e-06)
            else:
                return self.data == other.data
        else:
            return False

    def __str__(self):
        return '<{t}, {d}>'.format(t=self.type_id, d=self.data)

#    def __repr__(self):
#        return self.__str__()

    def encode(self):
        """
        Encode this TLV8 entry into a sequence of bytes.

        :return: a bytes instance
        :raises: ValueError if data to encode is not encodable (e.g. an Integer is bigger than 64 bit)
        """
        data_type = self.data_type
        if data_type == DataType.AUTODETECT:
            # detect the data type
            if isinstance(self.data, bytearray):
                data_type = DataType.BYTES
            if isinstance(self.data, bytes):
                data_type = DataType.BYTES
            if isinstance(self.data, float):
                data_type = DataType.FLOAT
            if isinstance(self.data, str):
                data_type = DataType.STRING
            if isinstance(self.data, int):
                data_type = DataType.INTEGER
            if isinstance(self.data, list):
                data_type = DataType.TLV8

        remaining_data = None
        if data_type == DataType.BYTES:
            remaining_data = self.data
        elif data_type == DataType.TLV8:
            remaining_data = encode(self.data)
        elif data_type == DataType.INTEGER:
            for int_format in ['<b', '<h', '<i', '<q']:
                try:
                    remaining_data = pack(int_format, self.data)
                    break
                except error:
                    pass
            if not remaining_data:
                raise ValueError('Integer {val} was to big for encoding'.format(val=self.data))
        elif data_type == DataType.FLOAT:
            remaining_data = pack('<f', self.data)
        elif data_type == DataType.STRING:
            remaining_data = self.data.encode()
        if remaining_data is None:
            raise ValueError('Data {val} of type {type} could not be encoded'.format(val=self.data, type=data_type))

        result = pack('<B', self.type_id)
        if len(remaining_data) == 0:
            result += b'\x00'
        else:
            while len(remaining_data) > 0:
                if len(remaining_data) < 256:
                    result += pack('<B', len(remaining_data))
                    result += remaining_data
                    remaining_data = []
                else:
                    result += b'\xff'
                    result += remaining_data[:255]
                    remaining_data = remaining_data[255:]
                    result += pack('<B', self.type_id)

        return result

    def format_string(self, indent=0):
        """
        Create a readable recursive string representation of this Entry object.

        :param indent: the indent used for the hierarchical structuring of the output
        :return: a str object representing this Entry instance
        """
        result = '<{i}, '.format(i=self.type_id)
        if self.data_type == DataType.TLV8 or isinstance(self.data, list):
            result += format_string(self.data, indent)
        else:
            result += str(self.data)
        result += '>,'
        return result
