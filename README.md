# SIMSG

SIMSG is a prototype of secure message exchange, using Signal protocol as end-to-end encryption, for the course of Advanced Security from University of Geneva.

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