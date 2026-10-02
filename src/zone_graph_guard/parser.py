"""Selected IN records, $ORIGIN, $TTL; all other dialects remain OPEN."""

from dataclasses import dataclass
import hashlib
import ipaddress
from .contracts import Gap
from .lexer import lex
from .names import parse_name, text_octets, wire

SUPPORTED = frozenset(("A", "AAAA", "NS", "CNAME", "DNAME", "SOA", "MX", "TXT", "PTR"))
UNITS = {ord("w"): 604800, ord("d"): 86400, ord("h"): 3600,
         ord("m"): 60, ord("s"): 1}


@dataclass(frozen=True)
class Record:
    owner: tuple
    kind: str
    ttl: int
    data: tuple
    location: object
    index: int

    def identity(self):
        parts = [wire(self.owner), self.kind.encode(), str(self.ttl).encode()]
        for value in self.data:
            parts.append(wire(value) if isinstance(value, tuple) else
                         value if isinstance(value, bytes) else str(value).encode())
        return hashlib.sha256(b"".join(len(p).to_bytes(4, "big") + p for p in parts)).hexdigest()


def number(raw, maximum, location):
    if not raw or not all(48 <= value <= 57 for value in raw) or len(raw) > 10:
        raise Gap("unsigned_decimal_required", location)
    result = int(raw)
    if result > maximum:
        raise Gap("numeric_range_exceeded", location)
    return result


def ttl_value(token):
    raw = token.raw.lower()
    if len(raw) > 63:
        raise Gap("time_token_size_exceeded", token.location)
    total, index = 0, 0
    while index < len(raw):
        end = index
        while end < len(raw) and 48 <= raw[end] <= 57:
            end += 1
        value = number(raw[index:end], 2147483647, token.location)
        if end < len(raw):
            multiplier = UNITS.get(raw[end])
            if multiplier is None:
                raise Gap("invalid_time_unit", token.location)
            total += value * multiplier
            index = end + 1
        else:
            if index:
                raise Gap("compound_time_requires_unit", token.location)
            total += value
            index = end
        if total > 2147483647:
            raise Gap("numeric_range_exceeded", token.location)
    if not raw:
        raise Gap("unsigned_decimal_required", token.location)
    return total


def domain(token, origin):
    if token.quoted:
        raise Gap("quoted_domain_unsupported", token.location)
    return parse_name(token.raw, origin, token.location)


def rdata(kind, tokens, origin, fallback_location):
    location = tokens[0].location if tokens else fallback_location
    sizes = {"A": 1, "AAAA": 1, "NS": 1, "CNAME": 1, "DNAME": 1,
             "PTR": 1, "SOA": 7, "MX": 2}
    if kind in sizes and len(tokens) != sizes[kind] or kind == "TXT" and not tokens:
        raise Gap("rdata_arity_error", location)
    if kind in ("A", "AAAA"):
        if tokens[0].quoted or b"%" in tokens[0].raw or b"\\" in tokens[0].raw:
            raise Gap("invalid_address", location)
        try:
            address = ipaddress.ip_address(tokens[0].raw.decode("ascii"))
        except ValueError:
            raise Gap("invalid_address", location) from None
        if address.version != (4 if kind == "A" else 6):
            raise Gap("address_family_mismatch", location)
        return (address.packed,)
    if kind in ("NS", "CNAME", "DNAME", "PTR"):
        return (domain(tokens[0], origin),)
    if kind == "MX":
        if tokens[0].quoted:
            raise Gap("quoted_number_unsupported", location)
        return (number(tokens[0].raw, 65535, tokens[0].location), domain(tokens[1], origin))
    if kind == "SOA":
        if any(token.quoted for token in tokens[2:]):
            raise Gap("quoted_number_unsupported", location)
        return (domain(tokens[0], origin), domain(tokens[1], origin),
                number(tokens[2].raw, 4294967295, tokens[2].location),
                *(ttl_value(token) for token in tokens[3:]))
    chunks = tuple(text_octets(token.raw, token.location) for token in tokens)
    if any(len(chunk) > 255 for chunk in chunks):
        raise Gap("txt_string_size_exceeded", location)
    return chunks


def parse_zone(raw, origin, source, limits):
    records = []
    current_origin, previous, default_ttl = origin, None, None
    try:
        for row in lex(raw, source, limits):
            tokens = list(row.tokens)
            first = tokens[0]
            if not first.quoted and first.raw.startswith(b"$"):
                if any(token.nesting for token in tokens):
                    raise Gap("grouped_directive_unsupported", first.location)
                command = first.raw.upper()
                if command not in (b"$ORIGIN", b"$TTL"):
                    raise Gap("unsupported_directive", first.location)
                if len(tokens) != 2 or tokens[1].quoted:
                    raise Gap("directive_arity_error", first.location)
                if command == b"$ORIGIN":
                    current_origin = domain(tokens[1], current_origin)
                else:
                    default_ttl = ttl_value(tokens[1])
                continue
            if row.omitted_owner:
                if previous is None:
                    raise Gap("omitted_owner_without_previous", first.location)
                owner = previous
            else:
                if tokens[0].nesting:
                    raise Gap("grouped_rr_header_unsupported", tokens[0].location)
                owner = domain(tokens.pop(0), current_origin)
                previous = owner
            rr_ttl, rr_class = None, None
            while tokens:
                token = tokens[0]
                value = token.raw.upper()
                if token.nesting:
                    raise Gap("grouped_rr_header_unsupported", token.location)
                if value in (b"IN", b"CH", b"HS"):
                    if rr_class is not None:
                        raise Gap("duplicate_rr_class", token.location)
                    rr_class = value
                    tokens.pop(0)
                elif token.raw and 48 <= token.raw[0] <= 57:
                    if rr_ttl is not None:
                        raise Gap("duplicate_rr_ttl", token.location)
                    rr_ttl = ttl_value(tokens.pop(0))
                else:
                    break
                if token.quoted:
                    raise Gap("quoted_rr_prefix_unsupported", token.location)
            if rr_class not in (None, b"IN"):
                raise Gap("unsupported_rr_class", first.location)
            if not tokens:
                raise Gap("missing_rr_type", first.location)
            type_token = tokens.pop(0)
            kind = type_token.raw.decode("ascii").upper()
            if type_token.quoted or kind not in SUPPORTED:
                raise Gap("unsupported_rr_type", type_token.location)
            if rr_ttl is None:
                rr_ttl = default_ttl
            if rr_ttl is None:
                raise Gap("explicit_or_default_ttl_required", first.location)
            records.append(Record(owner, kind, rr_ttl, rdata(kind, tokens, current_origin, type_token.location),
                                  first.location, len(records) + 1))
    except Gap as gap:
        return records, gap
    return records, None
