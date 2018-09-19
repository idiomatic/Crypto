-- Copyright 2018, r. brian harrison.  all rights reserved.

assert(bit)
local band    = bit.band
local bnot    = bit.bnot
local bor     = bit.bor
local bxor    = bit.bxor
local lshift  = bit.lshift
local rshift  = bit.rshift
local MAX_U32 = 0xffffffff

local function load_bigendian32(x, i)
    assert(i >= 1 and i + 3 <= #x)
    for j = 0, 3 do
        assert(x[i + j] >= 0 and x[i + j] <= 0xff)
    end

    return x[i] * 0x1000000 + x[i + 1] * 0x10000 + x[i + 2] * 0x100 + x[i + 3]
end

local function load_bigendian64(x, i)
    -- XXX inline
    return load_bigendian32(x, i), load_bigendian32(x, i + 4)
end

local function bigendian32(u)
    assert(u == floor(u))

    local d = u % 0x100
    u = (u - d) / 0x100
    local c = u % 0x100
    u = (u - c) / 0x100
    local b = u % 0x100
    return (u - b) / 0x100, b, c, d
end

local function store_bigendian32(x, i, u)
    assert(u >= 0 and u <= MAX_U32)
    assert(i >= 1)

    x[i], x[i + 1], x[i + 2], x[i + 3] = bigendian32(u)
end

local function store_bigendian64(x, i, hi, lo)
    assert(hi >= 0 and hi <= MAX_U32)
    assert(lo >= 0 and lo <= MAX_U32)

    -- XXX inline
    store_bigendian32(x, i, hi)
    store_bigendian32(x, i + 4, lo)
end

local function Ch(x, y, z)
    assert(x >= 0 and x <= MAX_U32)
    assert(y >= 0 and y <= MAX_U32)
    assert(z >= 0 and z <= MAX_U32)
    assert(x == floor(x))
    assert(y == floor(y))
    assert(z == floor(z))

    -- (x & y) ^ (~x & z)
    return bxor(band(x, y), band(bnot(x), z))
end

local function Maj(x, y, z)
    assert(x >= 0 and x <= MAX_U32)
    assert(y >= 0 and y <= MAX_U32)
    assert(z >= 0 and z <= MAX_U32)
    assert(x == floor(x))
    assert(y == floor(y))
    assert(z == floor(z))

    -- ((x & y) ^ (x & z) ^ (y & z))
    return bxor(band(x, y), band(x, z), band(y, z))
end

-- powers of 2, in absence of << operator
local P = {}
for i = 0, 31 do
    P[i] = lshift(1, i)
end

local function Sigma0(hi, lo)
    assert(hi >= 0 and hi <= MAX_U32)
    assert(lo >= 0 and lo <= MAX_U32)
    assert(hi == floor(hi))
    assert(lo == floor(lo))

    -- ROTR(x, 28) ^ ROTR(x, 34) & ROTR(x, 39)
    --local h = bxor(rshift(hi, 28) + lshift(lo, 4), lshift(hi, 30) + rshift(lo, 2), lshift(hi, 25) + rshift(lo, 7))
    local h = (bxor((hi - hi % P[28]) / P[28] + lo % P[28] * P[4],
                   hi % P[2] * P[30] + (lo - lo % P[2]) / P[2],
                   hi % P[7] * P[25] + (lo - lo % P[7]) / P[7]))
    --local l = bxor(rshift(lo, 28) + lshift(hi, 4), lshift(lo, 30) + rshift(hi, 2), lshift(lo, 25) + rshift(hi, 7))
    local l = (bxor((lo - lo % P[28]) / P[28] + hi % P[28] * P[4],
                   lo % P[2] * P[30] + (hi - hi % P[2]) / P[2],
                   lo % P[7] * P[25] + (hi - hi % P[7]) / P[7]))
    return h, l
end

local function Sigma1(hi, lo)
    assert(hi >= 0 and hi <= MAX_U32)
    assert(lo >= 0 and lo <= MAX_U32)
    assert(hi == floor(hi))
    assert(lo == floor(lo))

    -- ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)
    --local h = bxor(rshift(hi, 14) + lshift(lo, 18), rshift(hi, 18) + lshift(lo, 14), lshift(hi, 23) + rshift(lo, 9))
    local h = (bxor((hi - hi % P[14]) / P[14] + lo % P[14] * P[18],
                   (hi - hi % P[18]) / P[18] + lo % P[18] * P[14],
                   hi % P[9] * P[23] + (lo - lo % P[9]) / P[9]))
    --local l = bxor(rshift(lo, 14) + lshift(hi, 18), rshift(lo, 18) + lshift(hi, 14), lshift(lo, 23) + rshift(hi, 9))
    local l = (bxor((lo - lo % P[14]) / P[14] + hi % P[14] * P[18],
                   (lo - lo % P[18]) / P[18] + hi % P[18] * P[14],
                   lo % P[9] * P[23] + (hi - hi % P[9]) / P[9]))
    return h, l
end

local function sigma0(hi, lo)
    assert(hi >= 0 and hi <= MAX_U32)
    assert(lo >= 0 and lo <= MAX_U32)
    assert(hi == floor(hi))
    assert(lo == floor(lo))

    -- ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7)
    --local h = bxor(rshift(hi, 1) + lshift(lo, 31), rshift(hi, 8) + lshift(lo, 24), rshift(hi, 7))
    local h = (bxor((hi - hi % P[1]) / P[1] + lo % P[1] * P[31],
                (hi - hi % P[8]) / P[8] + lo % P[8] * P[24],
                (hi - hi % P[7]) / P[7]))
    --local l = bxor(rshift(lo, 1) + lshift(hi, 31), rshift(lo, 8) + lshift(hi, 24), rshift(lo, 7) + lshift(hi, 25))
    local l = (bxor((lo - lo % P[1]) / P[1] + hi % P[1] * P[31],
                (lo - lo % P[8]) / P[8] + hi % P[8] * P[24],
                (lo - lo % P[7]) / P[7] + hi % P[7] * P[25]))
    return h, l
end

local function sigma1(hi, lo)
    assert(hi >= 0 and hi <= MAX_U32)
    assert(lo >= 0 and lo <= MAX_U32)
    assert(hi == floor(hi))
    assert(lo == floor(lo))

    -- ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6)
    --local h = bxor(rshift(hi, 19) + lshift(lo, 13), lshift(hi, 3) + rshift(lo, 29), rshift(hi, 6))
    local h = (bxor((hi - hi % P[19]) / P[19] + lo % P[19] * P[13],
                   hi % P[29] * P[3] + (lo - lo % P[29]) / P[29],
                   (hi - hi % P[6]) / P[6]))
    --local l = bxor(rshift(lo, 19) + lshift(hi, 13), lshift(lo, 3) + rshift(hi, 29), rshift(lo, 6) + lshift(hi, 26))
    local l = (bxor((lo - lo % P[19]) / P[19] + hi % P[19] * P[13],
                   lo % P[29] * P[3] + (hi - hi % P[29]) / P[29],
                   (lo - lo % P[6]) / P[6] + hi % P[6] * P[26]))
    return h, l
end

-- carry overflow from low into hi, and truncate hi
local function carry(hi, lo)
    assert(hi == floor(hi))
    assert(lo == floor(lo))

    --local lo32 = bor(0, lo)
    local lo32 = lo % 0x100000000

    -- cannot use bit library as it is 32-bit, and the point of carry()
    -- is to carry lo's 32-bit overflow into hi.
    local c = (lo - lo32) / 0x100000000

    assert(lo32 == floor(lo32))
    assert(lo32 >= 0 and lo32 <= MAX_U32)
    assert(c >= 0)
    assert(c == floor(c))
    assert(lo == lo32 + c * 0x100000000)

    --return bor(0, hi + c), lo32
    return (hi + c) % 0x100000000, lo32
end

local K_hi = {
    {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174},
    {0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967},
    {0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070},
    {0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2},
    {0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f,
     0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
     0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4,
     0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c}
}

local K_lo = {
    {0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc,
     0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
     0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2,
     0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694},
    {0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
     0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
     0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4,
     0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70},
    {0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df,
     0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
     0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30,
     0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8},
    {0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8,
     0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
     0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
     0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b},
    {0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178,
     0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
     0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c,
     0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817}
}

function crypto_hashblock(s_hi, s_lo, m, offset)
    assert(#s_hi == 8)
    for i = 1, #s_hi do
        assert(s_hi[i] >= 0 and s_hi[i] <= MAX_U32)
    end
    assert(#s_lo == 8)
    for i = 1, #s_lo do
        assert(s_lo[i] >= 0 and s_lo[i] <= MAX_U32)
    end
    assert(#m - offset >= 128)
    assert(offset >= 0)

    -- XXX caution: allocation
    local ah_hi, ah_lo = {}, {} -- a thru h
    local w_hi, w_lo = {}, {}
    local s1_hi, s1_lo, ch_hi, ch_lo, s0_hi, s0_lo, maj_hi, maj_lo
    local t1_hi, t1_lo, t2_hi, t2_lo
    local r1, r9, r14

    for i = 1, 8 do -- #s_hi
        ah_hi[i], ah_lo[i] = s_hi[i], s_lo[i]
    end

    for i = 1, 16 do
        w_hi[i], w_lo[i] = load_bigendian64(m, offset + (i - 1) * 8 + 1)
    end

    for i = 1, 5 do -- #K_hi
        for r = 1, 16 do -- #K_hi[i]
            s1_hi, s1_lo = Sigma1(ah_hi[5], ah_lo[5])

            ch_hi = Ch(ah_hi[5], ah_hi[6], ah_hi[7])
            ch_lo = Ch(ah_lo[5], ah_lo[6], ah_lo[7])

            s0_hi, s0_lo = Sigma0(ah_hi[1], ah_lo[1])

            maj_hi = Maj(ah_hi[1], ah_hi[2], ah_hi[3])
            maj_lo = Maj(ah_lo[1], ah_lo[2], ah_lo[3])

            t1_hi, t1_lo = carry(
                ah_hi[8] + s1_hi + ch_hi + K_hi[i][r] + w_hi[r],
                ah_lo[8] + s1_lo + ch_lo + K_lo[i][r] + w_lo[r]
            )
            t2_hi, t2_lo = carry(s0_hi + maj_hi, s0_lo + maj_lo)

            ah_hi[8], ah_lo[8] = ah_hi[7], ah_lo[7]
            ah_hi[7], ah_lo[7] = ah_hi[6], ah_lo[6]
            ah_hi[6], ah_lo[6] = ah_hi[5], ah_lo[5]
            ah_hi[5], ah_lo[5] = carry(ah_hi[4] + t1_hi, ah_lo[4] + t1_lo)
            ah_hi[4], ah_lo[4] = ah_hi[3], ah_lo[3]
            ah_hi[3], ah_lo[3] = ah_hi[2], ah_lo[2]
            ah_hi[2], ah_lo[2] = ah_hi[1], ah_lo[1]
            ah_hi[1], ah_lo[1] = carry(t1_hi + t2_hi, t1_lo + t2_lo)
        end

        if i == 5 then -- #K_hi
            break
        end
        
        for r = 1, 16 do -- #w
            r1 = r % 16 + 1
            r9 = (r + 8) % 16 + 1
            r14 = (r + 13) % 16 + 1

            s0_hi, s0_lo = sigma0(w_hi[r1], w_lo[r1])
            s1_hi, s1_lo = sigma1(w_hi[r14], w_lo[r14])

            w_hi[r], w_lo[r] = carry(
                w_hi[r] + w_hi[r9] + s0_hi + s1_hi,
                w_lo[r] + w_lo[r9] + s0_lo + s1_lo
            )
        end
    end

    for i = 1, 8 do -- #s_hi
        s_hi[i], s_lo[i] = carry(ah_hi[i] + s_hi[i], ah_lo[i] + s_lo[i])
    end
end

local iv_hi = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
}

local iv_lo = {
    0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
    0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179
}

local function hash_initial_state()
    local s_hi, s_lo = {}, {}
    for i = 1, 16 do s_hi[i], s_lo[i] = iv_hi[i], iv_lo[i] end
    return s_hi, s_lo
end

local function hash_state_to_bytes(s_hi, s_lo)
    assert(#s_hi == 8)
    assert(#s_lo == 8)
    for i = 1, #s_hi do
        assert(s_hi[i] == floor(s_hi[i]))
    end
    for i = 1, #s_lo do
        assert(s_lo[i] == floor(s_lo[i]))
    end

    local out = {}
    for i = 1, 8 do -- #s_hi
        store_bigendian64(out, (i - 1) * 8 + 1, s_hi[i], s_lo[i])
    end

    assert(#out == 64)
    for i = 1, #out do
        assert(out[i] >= 0 and out[i] <= 0xff)
    end

    return out
end

function crypto_hash(m)
    local mlen = #m

    local s_hi, s_lo = hash_initial_state()

    local offset = 0
    local remain = mlen - offset
    while remain >= 128 do
        crypto_hashblock(s_hi, s_lo, m, offset)
        remain = remain - 128
        offset = offset + 128
    end

    local tail = {}
    for i = 1, remain do tail[i] = m[i + offset] end
    tail[remain + 1] = 0x80

    local tlen = (remain < 112 and 128 or 256)
    for i = remain + 2, tlen - 9 do tail[i] = 0 end
    store_bigendian64(tail, tlen - 8,
                      (mlen - mlen % 0x200000) / 0x200000,
                      (mlen - mlen % 0x20) % 0x200000 / 0x20)
    tail[tlen] = mlen % 0x20 * 0x8
    assert(#tail == tlen)

    crypto_hashblock(s_hi, s_lo, tail, 0)
    if tlen > 128 then
        crypto_hashblock(s_hi, s_lo, tail, 128)
    end

    return hash_state_to_bytes(s_hi, s_lo)
end

if _G.bytes_to_hex then
    function crypto_hash_string_to_hex(s)
        return bytes_to_hex(crypto_hash(string_to_bytes(s)))
    end
end
