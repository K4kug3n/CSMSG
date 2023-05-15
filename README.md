# SIMSG

SIMSG is a prototype of secure message exchange, using Signal protocol as end-to-end encryption, for the course of Advanced Security from University of Geneva.

## Build

This project use CMake as a project generator. To generate, use :
> cmake build

Then use the generate file for your compiler to build the project

## External library

- Boost multiprecision for integer with more than 64bits

## Logbook

28/03 - 04/04 :
- Implementation of key generation with Elliptic Curve25519 following RFC 7748

04/04 - 11/04 :
- Implementation of SHA512 following Nist paper
- Search about XEdDSA signature and but failed implementation
- Implementation of EdDSA signature folowing RFC 8032

11/04 - 18/04 :
- Implementation of XEdDSA signature following libsignal scheme
- Implementation of HKDF following RFC 5869
- Implementation of HMAC-SHA512 following RFC 2104

25/04 - 02/05 :
- Implementation of AES-256 block encryption with Nist test vector
- Add CBC encryption mode to AES
- Start report

02/05 - 09/05 :
- Implementation of Double Ratchet algorithm
- Continue report

09/05 - 16/05 :
- Finalize report
- Add initial message notion
- Finalize implementation