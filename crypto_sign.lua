-- Copyright 2018, r. brian harrison.  all rights reserved.

-- Lua 5.1 with World of Warcraft extensions/limitations
--
-- Integer operations are limited to 52-bit (IEEE 754) due to the
-- representation of all numbers as 64-bit floats.
--
-- bit library functions are limited to 32-bit as inputs are apparently
-- truncated.
--
-- Field elements and field groups are composed of 16-bit words that
-- sometimes overflows up to 36-bit intermediate values.
--
-- Scalar multiplication is special-case in that it takes a 256-bit
-- value composed of 32 8-bit bytes.

local crypto_debug = _G.crypto_debug

if crypto_debug then
    assert(randombytes)
    assert(bit)
    assert(crypto_verify_32)
end

local band    = bit.band
local bnot    = bit.bnot
local bor     = bit.bor
local bxor    = bit.bxor
local lshift  = bit.lshift
local rshift  = bit.rshift
local MIN_U32 = 0
local MAX_U32 = 0xffffffff
local MAX_U16 = 0xffff
local MAX_I52 = 0xfffffffffffff
local MIN_I52 = -0x1000000000000

local D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
           0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203}
local D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406}
local X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
           0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169}
local Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
           0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666}
local I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
           0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83}
local GF1 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
local GF0 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

-- car25519 carries and wraps-around 16-bit overflows
-- about 19480 invocations via crypto_sign()
-- modifies o[1..16] in place
local function car25519(o)
    if crypto_debug then
        assert(#o == 16)
        for i = 1, #o do
            assert(o[i] >= MIN_I52 and o[i] <= MAX_I52)
        end
    end

    local c

    -- ripple carries upwards
    for i = 1, 15 do
        --o[i+1], o[i] = carry16(o[i+1], o[i])
        c = (o[i] - o[i] % 0x10000) / 0x10000
        o[i] = o[i] - c * 0x10000
        o[i + 1] = o[i + 1] + c
    end

    -- wrap around overflow
    --c, o[16] = carry16(0, o[16])
    c = (o[16] - o[16] % 0x10000) / 0x10000
    o[16] = o[16] - c * 0x10000
    o[1] = o[1] + c * 38

    return o
end

-- sel25519 does a conditional swap:
-- (p, q, 0) => (p, q)
-- (p, q, 1) => (q, p)
-- possibly leaks timing
-- about 4104 invocations via crypto_sign()
local function sel25519(p, q, b)
    if crypto_debug then
        assert(#p == 16)
        assert(#q == 16)
        assert(b >= 0 and b <= 1)
    end

    if b == 0 then return p, q else return q, p end
end

local function load_littleendian16(x, i)
    if crypto_debug then
        for j = 0, 1 do
            assert(x[i + j] >= 0 and x[i + j] <= 0xff)
        end
    end

    return x[i] + x[i + 1] * 0x100
end

local function store_littleendian16(x, i, u)
    if crypto_debug then
        assert(u >= 0 and u <= MAX_U16)
    end

    x[i] = u % 0x100
    x[i + 1] = (u - x[i]) / 0x100 
end

-- about 4 invocations via crypto_sign()
local function pack25519_t(o, n)
    if crypto_debug then
        assert(#n == 16)
    end

    local m = {}
    local t = {unpack(n)}
    local b

    car25519(t)
    car25519(t)
    car25519(t)
    for _ = 1, 2 do
        m[1] = t[1] - 0xffed
        for i = 2, 15 do
            m[i] = t[i] - MAX_U16 - band(1, (rshift(m[i - 1], 16)))
            m[i - 1] = band(MAX_U16, m[i - 1])
        end
        m[16] = t[16] - 0x7fff - band(1, rshift(m[15], 16))
        b = band(1, rshift(m[16], 16))
        m[15] = band(MAX_U16, m[15])
        t, m = sel25519(t, m, 1 - b)
    end
    for i = 1, 16 do
        store_littleendian16(o, i * 2 - 1, t[i])
    end

    if crypto_debug then
        assert(#o == 32)
        for i = 1, #o do
            assert(o[i] >= 0 and o[i] <= 0xff)
        end
    end

    return o
end

local function pack25519(n) return pack25519_t({}, n) end

local function unpack25519_t(o, n)
    for i = 1, 16 do
        o[i] = load_littleendian16(n, i * 2 - 1)
    end
    o[16] = band(0x7fff, o[16])
    return o
end

local function unpack25519(n) return unpack25519_t({}, n) end

local function eq25519(a, b)
    local c = pack25519(a)
    local d = pack25519(b)
    return crypto_verify_32(c, d)
end

local function par25519(a)
    local d = pack25519(a)
    return band(0x1, d[1])
end

-- add two bigints
-- first operand is table to recycle
-- about 5120 invocations via crypto_sign()
local function add256_t(o, a, b)
    if crypto_debug then
        assert(#a == 16)
        assert(#b == 16)
    end
    
    for i = 1, 16 do o[i] = a[i] + b[i] end
    -- may have u16 overflow
    return o
end

local function add256(a, b) return add256_t({}, a, b) end

local function subtract256_t(o, a, b)
    if crypto_debug then
        assert(#a == 16)
        assert(#b == 16)
    end

    for i = 1, 16 do o[i] = a[i] - b[i] end
    -- may have u16 underflow
    return o
end

local function subtract256(a, b) return subtract256_t({}, a, b) end

-- adapted from https://github.com/golang/crypto/blob/master/ed25519/internal/edwards25519/edwards25519.go
-- about 9734 invocations via crypto_sign()
local function multiply256_t(o, a, b)
    if crypto_debug then
        assert(#a == 16)
        assert(#b == 16)
    end

    local o01, o02, o03, o04, o05, o06, o07, o08
    local o09, o10, o11, o12, o13, o14, o15, o16

    o01 = a[1]*b[1] + 38 * (a[2]*b[16] + a[3]*b[15] + a[4]*b[14] + a[5]*b[13] + a[6]*b[12] + a[7]*b[11] + a[8]*b[10] + a[9]*b[9] + a[10]*b[8] + a[11]*b[7] + a[12]*b[6] + a[13]*b[5] + a[14]*b[4] + a[15]*b[3] + a[16]*b[2])

    o02 = a[1]*b[2] + a[2]*b[1] + 38 * (a[3]*b[16] + a[4]*b[15] + a[5]*b[14] + a[6]*b[13] + a[7]*b[12] + a[8]*b[11] + a[9]*b[10] + a[10]*b[9] + a[11]*b[8] + a[12]*b[7] + a[13]*b[6] + a[14]*b[5] + a[15]*b[4] + a[16]*b[3])

    o03 = a[1]*b[3] + a[2]*b[2] + a[3]*b[1] + 38 * (a[4]*b[16] + a[5]*b[15] + a[6]*b[14] + a[7]*b[13] + a[8]*b[12] + a[9]*b[11] + a[10]*b[10] + a[11]*b[9] + a[12]*b[8] + a[13]*b[7] + a[14]*b[6] + a[15]*b[5] + a[16]*b[4])

    o04 = a[1]*b[4] + a[2]*b[3] + a[3]*b[2] + a[4]*b[1] + 38 * (a[5]*b[16] + a[6]*b[15] + a[7]*b[14] + a[8]*b[13] + a[9]*b[12] + a[10]*b[11] + a[11]*b[10] + a[12]*b[9] + a[13]*b[8] + a[14]*b[7] + a[15]*b[6] + a[16]*b[5])

    o05 = a[1]*b[5] + a[2]*b[4] + a[3]*b[3] + a[4]*b[2] + a[5]*b[1] + 38 * (a[6]*b[16] + a[7]*b[15] + a[8]*b[14] + a[9]*b[13] + a[10]*b[12] + a[11]*b[11] + a[12]*b[10] + a[13]*b[9] + a[14]*b[8] + a[15]*b[7] + a[16]*b[6])

    o06 = a[1]*b[6] + a[2]*b[5] + a[3]*b[4] + a[4]*b[3] + a[5]*b[2] + a[6]*b[1] + 38 * (a[7]*b[16] + a[8]*b[15] + a[9]*b[14] + a[10]*b[13] + a[11]*b[12] + a[12]*b[11] + a[13]*b[10] + a[14]*b[9] + a[15]*b[8] + a[16]*b[7])

    o07 = a[1]*b[7] + a[2]*b[6] + a[3]*b[5] + a[4]*b[4] + a[5]*b[3] + a[6]*b[2] + a[7]*b[1] + 38 * (a[8]*b[16] + a[9]*b[15] + a[10]*b[14] + a[11]*b[13] + a[12]*b[12] + a[13]*b[11] + a[14]*b[10] + a[15]*b[9] + a[16]*b[8])

    o08 = a[1]*b[8] + a[2]*b[7] + a[3]*b[6] + a[4]*b[5] + a[5]*b[4] + a[6]*b[3] + a[7]*b[2] + a[8]*b[1] + 38 * (a[9]*b[16] + a[10]*b[15] + a[11]*b[14] + a[12]*b[13] + a[13]*b[12] + a[14]*b[11] + a[15]*b[10] + a[16]*b[9])

    o09 = a[1]*b[9] + a[2]*b[8] + a[3]*b[7] + a[4]*b[6] + a[5]*b[5] + a[6]*b[4] + a[7]*b[3] + a[8]*b[2] + a[9]*b[1] + 38 * (a[10]*b[16] + a[11]*b[15] + a[12]*b[14] + a[13]*b[13] + a[14]*b[12] + a[15]*b[11] + a[16]*b[10])

    o10 = a[1]*b[10] + a[2]*b[9] + a[3]*b[8] + a[4]*b[7] + a[5]*b[6] + a[6]*b[5] + a[7]*b[4] + a[8]*b[3] + a[9]*b[2] + a[10]*b[1] + 38 * (a[11]*b[16] + a[12]*b[15] + a[13]*b[14] + a[14]*b[13] + a[15]*b[12] + a[16]*b[11])

    o11 = a[1]*b[11] + a[2]*b[10] + a[3]*b[9] + a[4]*b[8] + a[5]*b[7] + a[6]*b[6] + a[7]*b[5] + a[8]*b[4] + a[9]*b[3] + a[10]*b[2] + a[11]*b[1] + 38 * (a[12]*b[16] + a[13]*b[15] + a[14]*b[14] + a[15]*b[13] + a[16]*b[12])

    o12 = a[1]*b[12] + a[2]*b[11] + a[3]*b[10] + a[4]*b[9] + a[5]*b[8] + a[6]*b[7] + a[7]*b[6] + a[8]*b[5] + a[9]*b[4] + a[10]*b[3] + a[11]*b[2] + a[12]*b[1] + 38 * (a[13]*b[16] + a[14]*b[15] + a[15]*b[14] + a[16]*b[13])

    o13 = a[1]*b[13] + a[2]*b[12] + a[3]*b[11] + a[4]*b[10] + a[5]*b[9] + a[6]*b[8] + a[7]*b[7] + a[8]*b[6] + a[9]*b[5] + a[10]*b[4] + a[11]*b[3] + a[12]*b[2] + a[13]*b[1] + 38 * (a[14]*b[16] + a[15]*b[15] + a[16]*b[14])

    o14 = a[1]*b[14] + a[2]*b[13] + a[3]*b[12] + a[4]*b[11] + a[5]*b[10] + a[6]*b[9] + a[7]*b[8] + a[8]*b[7] + a[9]*b[6] + a[10]*b[5] + a[11]*b[4] + a[12]*b[3] + a[13]*b[2] + a[14]*b[1] + 38 * (a[15]*b[16] + a[16]*b[15])

    o15 = a[1]*b[15] + a[2]*b[14] + a[3]*b[13] + a[4]*b[12] + a[5]*b[11] + a[6]*b[10] + a[7]*b[9] + a[8]*b[8] + a[9]*b[7] + a[10]*b[6] + a[11]*b[5] + a[12]*b[4] + a[13]*b[3] + a[14]*b[2] + a[15]*b[1] + 38*a[16]*b[16]

    o16 = a[1]*b[16] + a[2]*b[15] + a[3]*b[14] + a[4]*b[13] + a[5]*b[12] + a[6]*b[11] + a[7]*b[10] + a[8]*b[9] + a[9]*b[8] + a[10]*b[7] + a[11]*b[6] + a[12]*b[5] + a[13]*b[4] + a[14]*b[3] + a[15]*b[2] + a[16]*b[1]

    o[1] = o01
    o[2] = o02
    o[3] = o03
    o[4] = o04
    o[5] = o05
    o[6] = o06
    o[7] = o07
    o[8] = o08
    o[9] = o09
    o[10] = o10
    o[11] = o11
    o[12] = o12
    o[13] = o13
    o[14] = o14
    o[15] = o15
    o[16] = o16

    return car25519(car25519(o))
end

local function multiply256(a, b) return multiply256_t({}, a, b) end

-- about 508 invocations via crypto_sign()
local function square256_t(o, a)
    if crypto_debug then
        assert(#a == 16)
    end

    return multiply256_t(o, a, a)
end

local function square256(a) return square256_t({}, a) end

-- about 2 invocations via crypto_sign()
local function inv25519_t(o, i)
    o = square256_t(o, i)
    for a = 5, 253 do
        o = square256_t(o, multiply256_t(o, o, i))
    end
    o = square256_t(o, o)
    o = square256_t(o, multiply256_t(o, o, i))
    o = square256_t(o, o)
    o = square256_t(o, multiply256_t(o, o, i))
    return multiply256_t(o, o, i)
end

local function inv25519(i) return inv25519_t({}, i) end

local function pow2523_t(o, i)
    local c = {unpack(i)}
    for a = 1, 249 do
        c = square256_t(c, c)
        c = multiply256_t(c, c, i)
    end
    c = square256_t(c, c)
    c = square256_t(c, c)
    return multiply256_t(o, c, i)
end

local function pow2523(i) return pow2523_t({}, i) end

-- about 500 invocations via crypto_sign()
local function addGF_t(o, p, q)
    local a, b, c, d, t = {}, {}, {}, {}, {}
    
    a = multiply256_t(a, subtract256_t(a, p[2], p[1]), subtract256_t(t, q[2], q[1]))
    b = multiply256_t(b, add256_t(b, p[1], p[2]), add256_t(t, q[1], q[2]))
    c = multiply256_t(c, multiply256_t(c, p[4], q[4]), D2)

    d = multiply256_t(d, p[3], q[3])
    d = add256_t(d, d, d)

    local e = subtract256(b, a)
    local f = subtract256(d, c)
    local g = add256(d, c)
    local h = add256(b, a)

    o[1] = multiply256_t(o[1] or a, e, f)
    o[2] = multiply256_t(o[2] or b, h, g)
    o[3] = multiply256_t(o[3] or c, g, f)
    o[4] = multiply256_t(o[4] or d, e, h)

    return o
end

local function addGF(p, q) return addGF_t({{}, {}, {}, {}}, p, q) end

-- possibly leaks timing
local function cswap(p, q, b)
    if b == 1 then return q, p else return p, q end
end

local function pack(p)
    local zi = inv25519(p[3])
    local tx = multiply256(p[1], zi)
    local ty = multiply256(p[2], zi)
    local r = pack25519(ty)
    r[32] = bxor(r[32], 0x80 * par25519(tx))
    return r
end

-- powers of 2, in absence of << operator
local P = {}
for i = 0, 7 do
    P[i] = lshift(0x1, i)
end

local function scalarmult(q, s)
    if crypto_debug then
        assert(#q == 4)
        for i = 1, #q do
            assert(#q[i] == 16)
        end
        assert(#s == 32)
    end

    -- copy
    q = {{unpack(q[1])}, {unpack(q[2])}, {unpack(q[3])}, {unpack(q[4])}}
    local p = {{unpack(GF0)}, {unpack(GF1)}, {unpack(GF1)}, {unpack(GF0)}}

    local b
    for i = 32, 1, -1 do
        for j = 7, 0, -1 do
            --b = band(lshift(1, j), s[i])
            b = (s[i] - s[i] % P[j]) / P[j] % 2

            if crypto_debug then
                assert(b == 0 or b == 1)
            end

            p, q = cswap(p, q, b)
            q = addGF_t(q, q, p)
            p = addGF_t(p, p, p)
            p, q = cswap(p, q, b)
        end
    end

    return p
end

local function scalarbase(s)
    local q = {X, Y, GF1, multiply256(X, Y)}
    return scalarmult(q, s)
end

-- 2^252 + 27742317777372353535851937790883648493
local L = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
           0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}

-- reduce computes x mod L
local function reduce(x)
    if crypto_debug then
        assert(#x == 64)
    end

    local r = {}

    local carry
    for i = 64, 33, -1 do
        carry = 0
        for j = i - 32, i - 13 do
            x[j] = x[j] + carry - 0x10 * x[i] * L[j - i + 33]
            carry = x[j] + 0x80
            carry = (carry - carry % 0x100) / 0x100
            x[j] = x[j] - carry * 0x100
        end
        x[i - 12] = x[i - 12] + carry
        x[i] = 0
    end

    carry = 0
    for i = 1, 32 do
        x[i] = x[i] + carry - (x[32] - x[32] % 0x10) / 0x10 * L[i]
        carry = (x[i] - x[i] % 0x100) / 0x100
        x[i] = x[i] % 0x100
    end

    for i = 1, 32 do x[i] = x[i] - carry * L[i] end

    for i = 1, 32 do
        x[i + 1] = x[i + 1] + (x[i] - x[i] % 0x100) / 0x100
        r[i] = x[i] % 0x100
    end

    return r
end

-- mulAdd is a low efficiency multiply ab+c without wrap-around ala multiply256
local function mulAdd(a, b, c)
    local x = {}

    for i = 1, 32 do
        x[i] = c[i]
        x[i + 32] = 0
    end
    for i = 1, 32 do
        for j = 1, 32 do
            x[i + j - 1] = x[i + j - 1] + a[i] * b[j]
        end
    end

    return x
end

function crypto_sign_keypair()
    local sk = randombytes(32)

    if crypto_debug then
        sk = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42}
    end
    
    local esk = crypto_hash(sk)
    esk[1] = band(0xf8, esk[1])
    esk[32] = bor(0x40, band(0x7f, esk[32]))

    local p = scalarbase({unpack(esk, 1, 32)})
    local pk = pack(p)

    for i = 1, 32 do sk[i + 32] = pk[i] end

    return pk, sk
end

function crypto_sign(m, sk)
    assert(#sk == 64)
    assert(type(m) == "table")

    local mlen = #m
    local eskm, esk = {}
    local mdm, mdr = {}
    local emdr
    local hm, h = {}
    local s, sm = nil, {}

    -- expanded secret key [tweetnacl d]
    for i = 1, 32 do eskm[i] = sk[i] end
    esk = crypto_hash(eskm)
    esk[1] = band(0xf8, esk[1])
    esk[32] = bor(0x40, band(0x7f, esk[32]))

    if crypto_debug then
        assert(#esk == 64)
    end

    -- messsage digest, reduced [tweetnacl r]
    for i = 1, 32 do mdm[i] = esk[i + 32] end
    for i = 1, mlen do mdm[i + 32] = m[i] end
    mdr = reduce(crypto_hash(mdm))

    if crypto_debug then
        assert(#mdr == 32)
    end

    -- XXX most of the time
    -- encoded message digest, reduced [tweetnacl sm[0]]
    emdr = pack(scalarbase(mdr))

    if crypto_debug then
        assert(#emdr == 32)
    end

    -- HRAM digest, reduced [tweetnacl h]
    for i = 1, 32 do hm[i] = emdr[i] end
    for i = 1, 32 do hm[i + 32] = sk[i + 32] end
    for i = 1, mlen do hm[i + 64] = m[i] end
    h = reduce(crypto_hash(hm))

    s = reduce(mulAdd(h, esk, mdr))

    -- signed message [tweetnacl sm]
    for i = 1, 32 do sm[i] = emdr[i] end
    for i = 1, 32 do sm[i + 32] = s[i] end
    for i = 1, mlen do sm[i + 64] = m[i] end

    return sm
end

local function unpackneg(pk)
    local r1 = unpack25519(pk)
    local num = square256(r1)
    local den = multiply256(num, D)
    num = subtract256(num, GF1)
    den = add256(den, GF1)
    local den2 = square256(den)
    local den4 = square256(den2)
    local den6 = multiply256(den4, den2)
    local r0 = multiply256(den6, num)
    r0 = multiply256(r0, den)
    r0 = pow2523(r0)
    r0 = multiply256(r0, num)
    r0 = multiply256(r0, den)
    r0 = multiply256(r0, den)
    r0 = multiply256(r0, den)

    local chk = square256(r0)
    chk = multiply256(chk, den)
    if not eq25519(chk, num) then r0 = multiply256(r0, I) end

    chk = square256(r0)
    chk = multiply256(chk, den)
    if not eq25519(chk, num) then return nil end

    if par25519(r0) == (pk[32] - pk[32] % 0x80) / 0x80 then
        r0 = subtract256(GF0, r0)
    end
    
    local r3 = multiply256(r0, r1)
    
    return {r0, r1, {unpack(GF1)}, r3}
end

function crypto_sign_open(sm, pk)
    local q = unpackneg(pk)
    if not q then return nil end

    local mdm = {unpack(sm)}
    for i = 1, 32 do mdm[i + 32] = pk[i] end
    local h = reduce(crypto_hash(mdm))
    local p = scalarmult(q, h)

    local mdr = {unpack(sm, 33, 64)}
    q = scalarbase(mdr)
    p = addGF_t(p, p, q)
    local t = pack(p)

    if not crypto_verify_32(sm, t) then return nil end

    return {unpack(sm, 65)}
end

if _G.bytes_to_string then
    function crypto_sign_string_to_string(s, sk)
        return bytes_to_string(crypto_sign(string_to_bytes(s), sk))
    end
    function crypto_sign_open_string(s, sk)
        return crypto_sign_open(string_to_bytes(s), sk)
    end
end

if crypto_debug then
    function dumpGF(g)
        return string.format("%s\n %s\n  %s\n   %s", hexdump16(g[1]), hexdump16(g[2]), hexdump16(g[3]), hexdump16(g[4]))
    end
end
