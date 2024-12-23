# MerkleLamportSignature
A small C language implementation of a Merkle Lamport Signature

This implements a [Merkle signature scheme](https://en.wikipedia.org/wiki/Merkle_signature_scheme) using a [Lamport signature](https://en.wikipedia.org/wiki/Lamport_signature).

This implementation was created to provide small code to fit in a memory constrained 32 bit microcontroller.
To handle more private data, change "unsigned int" in mls.h @ typedef unsigned int mlsSz_t; to, perhaps, "unsigned long".

Included is an example driver program, main.c, that uses the API in mls.h.

The supplied hash implementation must generate a power of 2 sized hash. The example driver program demonstrates rmd128 and sha256.
