# Type-Length-Value8 (TLV8) for python [![Build Status](https://travis-ci.org/jlusiardi/tlv8_python.svg?branch=master)](https://travis-ci.org/jlusiardi/tlv8_python) [![Coverage Status](https://coveralls.io/repos/github/jlusiardi/tlv8_python/badge.svg?branch=master)](https://coveralls.io/github/jlusiardi/tlv8_python?branch=master) 

Type-Length-Value (TLV) are used to encode arbitrary data. In this case the type and length are represented by 1 byte each. Hence the name TLV8.

A TLV8 entry consists of the following parts:

 * the **type**: this 8 bit field denotes the type of information that is represented by the data.
 * the **length**: this 8 bit field denotes the length of the data (this does not include the 2 bytes for type and length. For data longer than 255 bytes, there is a defined procedure available.
 * the **value**: these **length** bytes represent the value of this TLV. The different types of data is represented differently:
   * **bytes**: this is raw binary data and will be used as is, no further interpretation takes place
   * **tlv8**: this is a specialized case of  **bytes** values. Using this instead of pure bytes enables nesting of data and creating a hierarchy.
   * **integer**: integers are stored in little-endian byte order and are encoded with the minimal number of bytes possible (1, 2, 4 or 8)
   * **float**: floats are stored as little-endian ieee754 numbers
   * **string**: strings are always UTF-8 encoded and **do not** contain the terminating NULL byte

TLV8 entries whose content is longer than 255 bytes are split up into fragments. The type is repeated is repeated in each fragment, only the last fragment may contain less than 255 bytes. Fragments of one TLV8 entry must be continuous.

Multiple TLV8 entries can be combined to create larger structures. Entries of different types can placed one after another. Entries of the same type must be separated by a TLV8 entry of a different type (and probably zero length).

TLV8 entries of unknown or unwanted type are to be silently ignored.

## Examples 

### simple TLV8s

Encoding of some atomic examples:

 * an empty TLV of type 42: `[42, None]` will be encoded as `b'\x2a\x00'`.
 * a TLV of type 2 with 2 bytes `0x12, 0x34`: `[2, b'\x12\x34']` will be encoded as `b'\x02\x02\x12\x34'`
 * a TLV of type 3 that contains the TLV from above: `[3, [2, b'\x12\x34']]` will be encoded as `b'\x03\x04\x02\x02\x12\x34'`
 * a TLV of type 4 that contains 1024: `[4, 1024]` will be encoded as `b'\x04\0x02\x00\x04'`
 * a TLV of type 5 that contains 3.141: `[4, 3.141]` will be encoded as `b'\x04\x04\x0a\xd7\x23\x41'`
 * a TLV of type 23 with string `Hello 🌍`: `[23, 'Hello 🌍']` will be encoded as `b'\x17\x0a\x48\x65\x6c\x6c\x6f\x20\xf0\x9f\x8c\x8d'`

### fragmented TLV8s

Encoding of a fragmented TLV8 entry:

 * an TLV of type 6 that contains 256 bytes from 0 to 255: `[6, b'\x00\x01...\xfe\xff']` will be encoded as `b'\x06\xff\x00...\xfe\x06\x01\xff'`

### combined TLV8s

Encoding of two TLV8 Entries that follow each other in the input list:

 * the combination of 2 TLV8 entries (`[1, 123]` and `[2, 'Hello']`) will be encoded as `b'\x01\x01\x7b\x02\x05\x48\x65\x6c\x6c\x6f'`

### sequences of TLV8s of same type:

 * a sequence of 3 TLV8 entries of type 1 (`[1, 1]`, `[1, 2]` and `[1, 1]`) will be encoded as `b'\x01\x01\x01\xff\x00\x01\x01\x02\xff\x00\x01\x01\x03'`

## Using in code

There are two main use cases of this module.

### Create a bytes representation

Here we want to have a comfortable way to create a data structure in python and to encode this structure into a bytes value.

#### encode a simple list
For example, create a representation containing the following structure:
 
 * Type: 1, Value: 23
 * Type: 2, Value: 2345

This can be code like that:

```python
import tlv8

structure = [
    tlv8.Entry(1, 23),
    tlv8.Entry(2, 2345)
]
bytes_data = tlv8.encode(structure)
print(bytes_data)
```

And this will result in: `b'\x01\x01\x17\x02\x02)\t'`

#### Nesting structures

Representing a line ([x: 10, y: 20] - [x: 30, y: 40]) between to points could be represented like:

 * Type: 1, Value:
   * Type: 3, Value: 10 
   * Type: 4, Value: 20
 * Type: 2, Value:
   * Type: 3, Value: 30
   * Type: 4, Value: 40

```python
import tlv8

structure = [
    tlv8.Entry(1, [
        tlv8.Entry(3, 10),
        tlv8.Entry(4, 10),
    ]),
    tlv8.Entry(2, [
        tlv8.Entry(3, 30),
        tlv8.Entry(4, 40),
    ])
]
bytes_data = tlv8.encode(structure)
print(bytes_data)
```

And this will result in: `b'\x01\x06\x03\x01\n\x04\x01\n\x02\x06\x03\x01\x1e\x04\x01('`

### Decode a bytes representation

Decoding TLV8 entries from bytes data will return all bytes from all first level entries. This includes possible separator entries between entries of the same type.

Decoding can be assisted by hinting with an expected structure. To represent the structure in python `dict` objects are used and nested. The keys of the `dict` objects are the type ids of the TLV8 entries. If the id of an entry is not contained in the structure, it will be ignored.

#### decode the simple list

```python
import tlv8

in_data = b'\x01\x01\x17\x02\x02)\t'
expected_structure = {
    1: tlv8.DataType.INTEGER,
    2: tlv8.DataType.INTEGER
}
result = tlv8.decode(in_data, expected_structure)

print(tlv8.format_string(result))
```

This will result in:
```text
[
  <1, 23>,
  <2, 2345>,
]
```

#### decode nested data

```python
import tlv8

in_data = b'\x01\x06\x03\x01\n\x04\x01\n\x02\x06\x03\x01\x1e\x04\x01('
sub_struct = {
    3: tlv8.DataType.INTEGER,
    4: tlv8.DataType.INTEGER
}
expected_structure = {
    1: sub_struct,
    2: sub_struct
}
result = tlv8.decode(in_data, expected_structure)

print(tlv8.format_string(result))
```

This will result in:
```text
[
  <1, [
    <3, 10>,
    <4, 10>,
  ]>,
  <2, [
    <3, 30>,
    <4, 40>,
  ]>,
]
```

### Using IntEnum data during encoding and decoding

Using enumerations might increase readabilty of encode end decode processes.

### During encoding

It is possible to use `enum.IntEnum` for encoding:

```python
import tlv8
import enum

class Keys(enum.IntEnum):
    X = 42
    # ...

class Values(enum.IntEnum):
    Y = 23
    # ...

result = tlv8.encode([
    tlv8.Entry(Keys.X, Values.Y)
])

print(result)
```

This will result in:
```text
b'*\x01\x17'
```

### During decoding

As during encoding, `enum.IntEnum` can be used for keys and values during decoding:

```python
import tlv8
import enum

class Keys(enum.IntEnum):
    X = 42
    # ...

class Values(enum.IntEnum):
    Y = 23
    # ...

result = tlv8.decode(b'*\x01\x17', {
    Keys.X: Values
})

print(tlv8.format_string(result))
print(type(result[0].type_id), type(result[0].data))
```

This will result in 
```text
[
  <Keys.X, Values.Y>,
]
<enum 'Keys'> <enum 'Values'>
```

So the `type_id` and the `data` fields are not simple `int` instance anymore but values of their enumerations. This alos helps during using `format_string` to get a easier to read output.

## Coding

The module offers the following primary functions and classes.

### function `format_string`

This function formats a list of TLV8 Entry objects as str. The hierarchy of the entries will be represented by increasing the indentation of the output.

The parameters are:
 
 * `entries`: a python list of tlv8.Entries objects
 * `indent`: the level of indentation to be used, this defaults to 0 and is increased on recursive calls for nested entries.
 
The function returns a `str` instance and raises `ValueError` instances if the input is not a list of `tlv8.Entry` objects.

Example:
```python
import tlv8

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

This will become:
```text
[
  <1, 3.141>,
  <2, [
    <3, hello>,
    <4, world>,
  ]>,
  <1, 2>,
]
```

### function `encode`

Function to encode a list of `tlv8.Entry` objects into a sequence of bytes following the rules for creating TLVs. The `separator_type_id` is used for the separating entries between two entries of the same type. 

The parameters are:

 * `entries`: a list of `tlv8.Entry` objects
 * `separator_type_id`: the 8-bit type id of the separator to be used. The default is (as defined in table 5-6, page 51 of HomeKit Accessory Protocol Specification Non-Commercial Version Release R2) 0xff.

The function returns an instance of `bytes`. This is empty if nothing was encoded. The function raises `ValueError` if the input parameter is not a list of `tlv8.Entry` objects or a data value is not encodable. A `ValueError` will also be raised if the `separator_type_id` is used as `type_id` in one of the entries as well.

Example:
```python
import tlv8

data = [
    tlv8.Entry(1, 3.141),
    tlv8.Entry(2, [
        tlv8.Entry(3, 'hello'),
        tlv8.Entry(4, 'world')
    ]),
    tlv8.Entry(1, 2)
]
print(tlv8.encode(data))
```

This will result in:
```text
b'\x01\x04%\x06I@\x02\x0e\x03\x05hello\x04\x05world\x01\x01\x02'
```

### function `decode`

Function to decode a `bytes` or `bytearray` instance into a list of `tlv8.Entry` instances. This reverses the process done by the `encode` function.

The parameters are:

 * `data`: a `bytes` or `bytearray` instance to be parsed
 * `expected`: a dict of type ids onto expected `tlv8.DataType` values. If the expected entry is again a `tlv8.Entry` that should be parsed, use another dict to describe the hiearchical structure. This defaults to `None` which means not filtering will be performed but also no interpretation of the entries is done. This means they will be returned as `bytes` sequence.
 * `strict_mode`: This defaults to `False`. If set to `True`, this will raise additional `ValueError` instances if there are possible missing separators between entries of the same type.

The function returns a `list` instance and raises `ValueError` instances if the input is either not a `bytes` object or an invalid tlv8 structure.

Example:
```python
import tlv8

data = b'\x01\x04%\x06I@\x02\x0e\x03\x05hello\x04\x05world\x03\x01\x02'

structure = {
        1: tlv8.DataType.FLOAT,
        2: {
            3: tlv8.DataType.STRING,
            4: tlv8.DataType.STRING
        },
        3: tlv8.DataType.INTEGER
    }

print(tlv8.decode(data, structure))
```

This will result in:
```text
[
  <1, 3.1410000324249268>,
  <2, [
    <3, hello>,
    <4, world>,
  ]>,
  <3, 2>,
]
```

### class `DataType`

This enumeration is used to represent the data type of a `tlv8.Entry`. 

Enumeration Entry | TLV8 type | Python type
---               | ---       | ---
BYTES             | bytes     | `bytes`, also `bytearray` for encoding
TLV8              | tlv8      | custom class `tlv8.Entry` for encoding and `dict` for the expected structure during decoding
INTEGER           | integer   | `int`
FLOAT             | float     | `float`
STRING            | string    | `str`
AUTODETECT        | n/a       | this is used declare that a data type is not preset but will be determined by the python type of the data


### class `Entry`

This class represents a single entry in a TLV8 data set. The class overrides the methods `__eq__`, `__str__` and `__repr__` to fit the needs of the application.

#### constructor

The constructor takes the following parameters:

 * `type_id`: the type id of the entry. Must be between 0 and 255 (8-bit type id).
 * `data`: the data to be stored in this entry. 
 * `data_type`: the data type of the entry. Defaults to `DataType.AUTODETECT`.
 * `length`: if set, this overrides the automatic length detection. This used for integer, when there is special need to set higher byte count than the value would need.
 
The constructor raises a `ValueError` if the `type_id` is not within the 8-bit range.

#### `encode() -> bytes`

This function is called to encode the data stored in this `Entry`. The data type of the data will be used to decide how to encode the data. It uses the `tlv8.encode()` function to encode nested lists of `tlv8.Entry` objects. 

#### `format_string() -> str`

This function formats the data stored in this entry as readable string. It is mostly called by `tlv8.format_string()`.

### class `EntryList`

This class represents a list of entries. The class overrides the methods `__repr__`, `__eq__`, `__len__`, `__getitem__` and `__iter__` to fit the needs of the application. 

#### constructor

The constructor takes the following parameters:

 * `data`: if set, this `list` of `tlv8.Entry` instances is used to initialize the `EntryList`.

The constructor raised a `ValueError` if the data is either not a `list` or not a list of `tlv8.Entry` instances.

#### `append(entry)`

Append the `tlv8.Entry` to the `EntryList`. It performs type checks, so only `tlv8.Entry` instances can be appended.

#### `assert_has(type_id, message)`

Looks for a `tlv8.Entry` instance with `type_id` in the first level of the `EntryList`. If none is found, it raises an `AssertionError` with the given `message`. This does not iterate recursivly, because the same type id may have different meanings on different levels (and different contexts).

#### `encode(self, separator_type_id)`

Encodes the `EntryList` using the given separator type id. This relies on `tlv8.encode()`.

#### `by_id(type_id)`

Filters the `EntryList` and returns only `Entry` instance whose `type_id` match the given one. If no `Entry` instances
were found it returns an empty list.

#### `first_by_id(type_id)`

Search the `EntryList` for the first `Entry` with the given `type_id`. If no such `Entry` was found, it returns `None`.
