# MerkleLamportSignature
A small C language implementation of a Merkle Lamport Signature

This implements a [Merkle signature scheme](https://en.wikipedia.org/wiki/Merkle_signature_scheme) using a [Lamport signature](https://en.wikipedia.org/wiki/Lamport_signature).

This implementation was created to provide small code to fit in a memory constrained 32 bit microcontroller.
To handle more private data, change "unsigned int" in mls.h @ typedef unsigned int mlsSz_t; to, perhaps, "unsigned long".

Included is an example driver program, main.c, that uses the API in mls.h.

The supplied hash implementation must generate a power of 2 sized hash.
The example driver program demonstrates rmd128 and sha256.

The amount of private data and the signature size is dependent on the size of the hash and the number of signings desired to a signing hash.

For example, using a 128 bit, (2^5 = 16 byte) hash and signing a single message to a 128 bit signing hash:

./mls128 0 0 </dev/zero

* signings: 2^0 = 1, use signing: 0
* privateDataSize: 4096, signatureSize: 4098, workAreaSize: 119

The signature is not small but grows slowly as the number of desired signings increases.
For example to sign 1024 messages:

./mls128 10 0 </dev/zero

* signings: 2^10 = 1024, use signing: 0
* privateDataSize: 4194304, signatureSize: 4268, workAreaSize: 459

The private data gets larger but the signature size only increases 4268 - 4098 = 170 bytes.
Taking the number of signings to 65536 messages:

./mls128 16 0 </dev/zero

signings: 2^16 = 65536, use signing: 0
privateDataSize: 268435456, signatureSize: 4370, workAreaSize: 663

The private data is very large, 256 MB, but the signature size only increases another 4370 - 4268 = 102 bytes.

Signing a message is as expensive as generating the signing hash.
Verifying a signature is inexpensive.

For the 65536 example, to sign a message the hash function is called 33,554,032 times!
An alternative would be to keep the intermediate data (entire Merkle tree) from generating the signing hash, double the private data size.
For this example, it would be an additional 512 MB of data!
Fortunately, verifying this signature is, relatively, inexpensive with only 399 calls to the hash function.
