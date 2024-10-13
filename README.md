# schnorr-pz

This repository contains an implementation of Schnorr signatures in multiparty FHE (MP-FHE) using the [Phantom Zone](https://github.com/gausslabs/phantom-zone) library. 
Along the way, it also contains a general implementation of FheUints (as opposed to `phantom-zone`'s FheUint8s). These FheUints can have arbitrary size, and have fast multiplication
using Karatsuba multiplication.
Additionally, they are composed of `PossiblyFheBools`, which can be either plaintext or FHE. This allows us to avoid key-switching on publicly known values (e.g. when this is the signed message, this can actually provide significant performance improvements).

Outstanding TODOs:
- The hash function used is very primitive (and is clearly unsafe). It is currently used as a proof-of-concept.
- The implementation of FheUints can be improved. There is a lot of memory cloning, which ends up being very expensive. We should replace this with passing by reference when possible.