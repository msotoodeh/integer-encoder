# integer-encoder
Ayden32/64 Integer Encoder
==========================

Copyright Mehdi Sotoodeh.  All rights reserved.
<mehdisotoodeh@gmail.com>

This code and accompanying files are put in public domain by the author.
You are free to use, copy, modify and distribute this software as long
as you comply with the license terms. See license.txt file for details.


This a proprietary, lightweight and high performance integer encoder. 
Currently 32 and 64 bit integer encryption/decryption are provided but
it is generic enough that can be applied to any integer size.

To use this library, you may include the required library sources or
use it as a static or dynamic library. See the demo file in the test
folder.

The API is simple. You initialize the key context (state information)
using your secret key and then use encrypt or decrypt interfaces for 
the integer size of your choice.


Knwon Answer Tests:
```
    KAT: i32encoder ...
    00000000 --E--> dd88efec --D--> 00000000 -- PASS
    00000001 --E--> 9c3af872 --D--> 00000001 -- PASS
    10000000 --E--> 2bedadb3 --D--> 10000000 -- PASS
    44e0aac2 --E--> 108aa84a --D--> 44e0aac2 -- PASS
    8bcfe6af --E--> 2fe50f00 --D--> 8bcfe6af -- PASS
    2434b90b --E--> 31cd013c --D--> 2434b90b -- PASS
    e5d02a2a --E--> e2133d51 --D--> e5d02a2a -- PASS
    266c9a72 --E--> 92a28d83 --D--> 266c9a72 -- PASS
    156769bc --E--> f097563f --D--> 156769bc -- PASS
    a57c5777 --E--> cc0c5db0 --D--> a57c5777 -- PASS
    
    KAT: i64encoder ...
    0000000000000000 --E--> f13fcadb0422ac00 --D--> 0000000000000000 -- PASS
    0000000000000001 --E--> bb632c03d107b9bf --D--> 0000000000000001 -- PASS
    0000000000000010 --E--> 879dd8f434557e8e --D--> 0000000000000010 -- PASS
    9999999999999999 --E--> 6b7f89de31467cc3 --D--> 9999999999999999 -- PASS
    931deb4ceb4802b6 --E--> 001030484a3265a6 --D--> 931deb4ceb4802b6 -- PASS
    5e046fe51654b354 --E--> cd57eec3d5230573 --D--> 5e046fe51654b354 -- PASS
    f22ab69390799033 --E--> 9a13f3c575cf8e12 --D--> f22ab69390799033 -- PASS
    8ab554aca02eae5f --E--> fa75b0d449c138a0 --D--> 8ab554aca02eae5f -- PASS
    8801f649c7ebf6c5 --E--> e8076a3e6173be3d --D--> 8801f649c7ebf6c5 -- PASS
    09f43ac6689830e2 --E--> 134640b5807035d8 --D--> 09f43ac6689830e2 -- PASS
```

You have the option of pre-generating one or more key context blobs and 
embedding them directly into your code. This gives you the best performance 
since you do not need to load your key every time you want to encrypt or 
decrypt a number.

