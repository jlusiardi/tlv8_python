
# Changes

## Version 0.9.0

Bug Fix:

- Fix for https://github.com/jlusiardi/tlv8_python/issues/13 (and https://github.com/jlusiardi/homekit_python/issues/194)
  which broke pairing with BLE devices.

## Version 0.8.0

New Features:

 - `tlv8.encode` can now handle lists of `tlv8.Entry` objects and
   `tlv8.EntryLists`
 - adds `tlv8.JsonEncoder` to serialize `tlv8.Entry` and
   `tlv8.EntryList` objects to json where needed


## Version 0.7.0

New Features:

 - Add data type `tlv8.DataType.UNSIGNED_INTEGER` to make a distinction between the default of 
   signed integers and unsigned integer. This is important for read network ports from TLV 
   structures

## Version 0.6.0

New Features:

 - Add function `tlv8.deep_decode` to get a quick view over a TLV structure.

## Version 0.5.0

New Features:

 - Integration of Coveralls into build pipeline
 - Add new type `tlv8.EntryList` to have easier access to entries in a TLV list

## Version 0.4.0

New Features:

 - Support encoding and decoding `IntEnum` keys and and values

## Version 0.3.0

New Features:

 - `tlv8.decode` now can decode bytearray instances

## Version 0.2.0

New Features:

 - `tlv8.Entry.encode` now handles also bytearray instances as input for TLV Datatype bytes


## Version 0.1.0

Initial release to the public.

