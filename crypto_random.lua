-- Copyright 2018, r. brian harrison.  all rights reserved.

function randombytes(n)
    local data = {}
    for i = 1, n do
        data[i] = random(0, 0xff)
    end
    return data
end
