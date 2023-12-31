<div align="center">
  <div>
    <a href="https://github.com/K4kug3n/CSMSG/actions?query=workflow%3Awindow">
      <img src="https://github.com/K4kug3n/CSMSG/workflows/window/badge.svg" alt="github-ci" />
    </a>
    <a href="https://github.com/K4kug3n/CSMSG/actions?query=workflow%3Alinux">
      <img src="https://github.com/K4kug3n/CSMSG/workflows/linux/badge.svg" alt="github-ci" />
    </a>
  </div>
</div>

# CSMSG

CSMSG is a small implementation of Signal protocol as a prototype of secure message exchange, for the course of Advanced Security from University of Geneva.

## Realisation

- Key generation with Elliptic Curve25519 following RFC 7748
- SHA512 following Nist paper
- EdDSA signature folowing RFC 8032
- XEdDSA signature following libsignal scheme
- HKDF following RFC 5869
- HMAC-SHA512 following RFC 2104
- AES-256 block encryption with Nist test vector
- CBC encryption mode to AES
- Double Ratchet algorithm

## Build

This project can use CMake as a project generator. To generate, use :
> cmake -B./build/ .

Then use the generated files in `./build/` for your compiler to build the project.  

This project can also be used with xmake as build utility.  

Use C++17.

## External library

- Boost multiprecision for integer with more than 64bits
- Catch2 for unit tests