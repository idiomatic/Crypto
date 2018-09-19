-- Copyright 2018, r. brian harrison.  all rights reserved.

assert(bit)
local bor    = bit.bor
local bxor   = bit.bxor

local function verify_n(x, y, n)
    assert(#x >= n)
    assert(#y >= n)

    local differentbits = 0

    for i = 1, n do
        differentbits = bor(differentbits, bxor(x[i], y[i]))
    end

    -- XXX possibly leaks timing
    return differentbits == 0
end

function crypto_verify_16(x, y)
    return verify_n(x, y, 16)
end

function crypto_verify_32(x, y)
    return verify_n(x, y, 32)
end
