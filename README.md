# NaCl-like Cryptography Library for World of Warcraft Lua

[NaCl](https://nacl.cr.yp.to) is a easy-to-use high-speed software
library for encryption, signatures, *et al*.

[World of Warcraft](https://worldofwarcraft.com/) is a massively
multiplayer online role-playing game.

[Lua](https://www.lua.org/) is a lightweight programming language well
suited for embedding into applications.

World of Warcraft wisely (up until now) empowered the players access
to an game client API through add-ons written in Lua.  Missing from
this client is cryptographic primitives and big (or even small)
integer math... until now.

**DISCLAIMER** This is not endorsed by the NaCl core developers.

**DISCLAIMER** This is not fully implemented.  Priority is given to
implementing hashing and signing.

**DISCLAIMER** This is not fully hardened against
[timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

**DISCLAIMER** This is not fully optimized, nor is there much
expectation of much improvement to be had while using only floating
point numbers, interpreted math primitives, and algebraic bit
operations.

**DISCLAIMER** This is not multitasking yet.  Ideally the client
should not freeze perceptibly while doing typical operations.

# Why

World of Warcraft is a complex "game".  It is full of cooperative and
competitive player-to-player interaction, resource and time
management, personal development and augmentation,
[metagaming](https://en.wikipedia.org/wiki/Metagaming), and
dissemination of information of various levels of credibility and
convenience.  This library aims to directly and indirectly touch on
all those aspects.

## Objective

Trusted
[real-time](https://en.wikipedia.org/wiki/Real-time_computing#Near_real-time)
distribution of information (including
[code](https://en.wikipedia.org/wiki/Stored-program_computer)) within
the client extends the capabilities of World of Warcraft.

## Use Cases

### Player Identification

Certain players (*e.g.*, add-on developers) may wish to be identified,
perhaps as immediately as upon character rolling.  However, character
names are not global, and thus there is a chance a [hard
coded](https://en.wikipedia.org/wiki/Hard_coding) character name is
already taken on a realm.  Alternatively, a published public key can
be applied to an add-on-channel broadcasted announcement message
originating from the public player.

### Data Croudsourcing

Once a character has been identified, an add-on developer can collect
buffered messages from add-on users.

### Tipping

A player providing a useful service may receive in-game currency tips
by identifying themselves and embedding a mailbox hook.  It is
recommended that a non-invasive user-centric-designed player-sensitive
UI be present, otherwise the add-on risks becoming spurned &mdash; and
other add-ons with tipping that respects the player are tainted.

### Man-in-the-Middle Communication

A character may wish to send information to another character through
an intermediary.  The intermediary might be untrusted, and/or the
destination character might be on a different realm visited by the
intermediary.

### Code Distribution

Lua code may be packaged and signed in a way to facilitate nearly
instantaneous updates.

# API

## Hashing

### crypto_hash(a)

`crypto_hash()` is a hash function that takes a "message" (an array of
any length of 8-bit bytes) and computes a fixed-sized "hash" value
(512-bit value split into an array of sixteen 16-bit numbers).  This
computed value is unique enough for strong cryptography.  Except for
the most trivial (*i.e.*, predictable) of messages, it is hard to
determine the original message merely from the hash.

``` lua
m = string_to_bytes("hello, world!")
h = crypto_hash(m)
```

Implemented as [SHA-512](https://en.wikipedia.org/wiki/SHA-2).

## Signatures

### crypto_sign_keypair()

`crypto_sign_keypair()` generates a random "secret" private key and
corresponding "sharable" public key.  The private key is a 512-bit
value split into an array of sixty-four 8-bit bytes), with a 256-bit
secret random number and a copy of the 256-bit public key.
Distribution of public keys is beyond the scope of this library.

``` lua
pk, sk = crypto_sign_keypair()
```

### crypto_sign(m, sk)

`crypto_sign()` converts a message to a slightly-larger signed
message.  The original message is
[plaintext](https://en.wikipedia.org/wiki/Plaintext) and starts after
the signature.  The signature is sixty-four bytes long but could
change; extract the message using
[`crypto_sign_open()`](#crypto_sign_open).

``` lua
m = string_to_bytes("proclamation")
sm = crypto_sign(m, sk)
```

### crypto_sign_open(sm, pk)

`crypto_sign_open()` converts a signed message back to a message.  May
return a false value if the signature is invalid or the message has
been tampered.  Signed messages can be verified without revealing the
signer's private key.

``` lua
a2 = crypto_sign_open(sm, pk)
if a2 then
	m2 = bytes_to_string(a2)
end
```

Implemented as an [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) over [Curve25519](https://en.wikipedia.org/wiki/Curve25519) with [SHA-512](https://en.wikipedia.org/wiki/SHA-2).

## Encoding

### string_to_bytes(s)

`string_to_bytes()` splits a string into an array of bytes.

``` lua
a = string_to_bytes(s)
```

### bytes_to_string(a)

`bytes_to_string()` merges an array of bytes into a string.

``` lua
s = bytes_to_string(a)
```

### bytes_to_hex(a)

`bytes_to_hex()` merges an array of bytes into a hexadecimal string.

``` lua
s = bytes_to_hex(a)
```

# Implementation Details

## Bitwise Operations

There is no bitwise operations (e.g., `<<`).  However, there is a
`bit` library of limited utility:

* inputs are apparently truncated to fit within 0 to 2<sup>32</sup>-1.
* the operations are functions, which incurs approximate overhead of 120ns.

An alternative is to use algebraic operations to simulate bitwise operations:

| C                      | bit                | algebraic               |
|------------------------|--------------------|-------------------------|
| `a << b` (overflowing) | n/a                | `a * 2**b`              |
| `a << b` (truncating)  | `bit.lshift(a, b)` | `a % 2**(32-b) * 2**b`  |
| `a >> b` (logical)     | `bit.rshift(a, b)` | `(a - a % 2**b) / 2**b` |
| `a \| b` (no overlap)  | `bit.bor(a, b)`    | `a + b`                 |

The floating-point division and modulo operations are apparently
faster than function calls to simple logical operations.

## Floating Point Numerics

There is no `integer` type, just `number`.  As a result, numbers are
integer-precise to about 2<sup>52</sup>.

## Big Integers

There is no native representation of integers bigger than
2<sup>52</sup>.  The work-around is to represent a big integer value
as an array of numbers, where each array element represents a
[signed](https://en.wikipedia.org/wiki/Signedness) slice of that
number.  [Overflow](https://en.wikipedia.org/wiki/Integer_overflow) is
accommodated by using 16-bit slices, allowing a sum of a few squares
of ±2<sub>16</sub> numbers before having to carry overflows.

## Table Recycling

Table allocation is a costly operation, taking approximately 380ns.
Many "hot" functions take a table to recycle for their return value.
The table recycling functions are safe using the same "output" table
as one of the "inputs".

## Loop Unraveling

Unlooping the "long multiplication" algorithm in multiply256_t() into
a non-looping humongous block of code resulted in >5x improvement.
Thanks for the example, Go core developers!

## Random

There is
[speculation](https://www.mmo-champion.com/threads/2270845-math-random-can-t-generate-a-good-random-number-since-it-uses-C-rand()?p=46904173&viewfull=1#post46904173)
that the World of Warcraft Lua API uses a non-standard (*i.e.*,
potentially better for crypto) math.random().
