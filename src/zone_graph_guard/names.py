"""DNS labels are octets; escaped dots are not label separators."""

import hashlib
from .contracts import Gap

LOWER = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")


def units(raw, location):
    index = 0
    while index < len(raw):
        value = raw[index]
        escaped = False
        if value == 92:
            index += 1
            if index == len(raw):
                raise Gap("truncated_escape", location)
            escaped = True
            if 48 <= raw[index] <= 57:
                digits = raw[index:index + 3]
                if len(digits) != 3 or not all(48 <= d <= 57 for d in digits):
                    raise Gap("decimal_escape_requires_three_digits", location)
                value = int(digits)
                if value > 255:
                    raise Gap("decimal_escape_out_of_range", location)
                index += 2
            else:
                value = raw[index]
        yield value, escaped
        index += 1


def wire(name):
    return b"".join(bytes((len(label),)) + label for label in name) + b"\0"


def name_id(name):
    return hashlib.sha256(wire(name)).hexdigest()


def within(name, suffix, strict=False):
    return (len(name) > len(suffix) if strict else len(name) >= len(suffix)) and (
        not suffix or name[-len(suffix):] == suffix)


def parse_name(raw, origin, location, *, absolute=False):
    if raw == b"@" and not absolute:
        return origin
    if raw == b".":
        return ()
    labels = []
    current = bytearray()
    last_dot = False
    for value, escaped in units(raw, location):
        if not escaped and (value >= 127 or value <= 32 or value in b';()"'):
            raise Gap("unsupported_name_presentation", location)
        if value == 46 and not escaped:
            if not current:
                raise Gap("empty_dns_label", location)
            labels.append(bytes(current).translate(LOWER))
            current.clear()
            last_dot = True
        else:
            current.append(value)
            last_dot = False
    if current:
        labels.append(bytes(current).translate(LOWER))
    if not labels:
        raise Gap("empty_dns_name", location)
    if absolute and not last_dot:
        raise Gap("absolute_dns_name_required", location)
    if not last_dot:
        labels.extend(origin)
    name = tuple(labels)
    if any(len(label) > 63 for label in name) or len(wire(name)) > 255:
        raise Gap("dns_name_size_exceeded", location)
    return name


def text_octets(raw, location):
    return bytes(value for value, _ in units(raw, location))
