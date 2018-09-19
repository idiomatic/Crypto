# NaCl port to World of Warcraft Lua

[NaCl](https://nacl.cr.yp.to) is a easy-to-use high-speed software
library for encryption, signatures, et al.

[World of Warcraft](https://worldofwarcraft.com/) is a massively
multiplayer online role-playing game.

[Lua](https://www.lua.org/) is a lightweight programming language well
suited for embedding into applications.

World of Warcraft wisely (up until now) empowered the players access
to an game client API through add-ons written (primarily) in a
modified Lua 5.1.  Missing from this client is cryptographic
primitives and big (or even small) integer math... until now.

**DISCLAIMER** This is not fully implemented.  Priority is given to
implementing hashing and signing.

**DISCLAIMER** This is not fully hardened against
[timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

**DISCLAIMER** This is not fully optimized, nor is there much
expectation of much improvement to be had while using only floating
point numbers, interpreted math primitives, and algebraic bit
operations.

**DISCLAIMER** This is not multitasking yet.  Ideally the client
should not freeze perceptibly to the end-user.
