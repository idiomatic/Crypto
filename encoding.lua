-- Copyright 2018, r. brian harrison.  all rights reserved.

function string_to_bytes(s)
    return {string.byte(s, 1, string.len(s))}
end

function bytes_to_string(a)
    local out = {}
    for _, b in ipairs(a) do
        table.insert(out, string.char(b))
    end
    return table.concat(out)
end

function bytes_to_hex(a)
    return string.format(string.rep("%02X", #a), unpack(a))
end
