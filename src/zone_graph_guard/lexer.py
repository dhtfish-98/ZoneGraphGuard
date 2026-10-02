"""Byte lexer for bounded, local BIND-style master-file logical records."""

from dataclasses import dataclass
from .contracts import Gap, Location


@dataclass(frozen=True)
class Token:
    raw: bytes
    quoted: bool
    location: Location
    nesting: int


@dataclass(frozen=True)
class Row:
    tokens: tuple
    omitted_owner: bool


def lex(raw, source, limits):
    index, line, column, depth, count, rows = 0, 1, 1, 0, 0, 0
    tokens = []
    omitted = False
    start = True

    def loc():
        return Location(source, line, column, index)

    def advance():
        nonlocal index, line, column
        if raw[index] == 10:
            line += 1
            column = 1
        else:
            column += 1
        index += 1

    while index < len(raw):
        value = raw[index]
        if value >= 127 or value < 32 and value not in (9, 10, 13):
            raise Gap("unsupported_raw_character", loc())
        if value in (32, 9):
            if start:
                omitted = True
            advance()
            continue
        if value == 13:
            if index + 1 == len(raw) or raw[index + 1] != 10:
                raise Gap("bare_carriage_return", loc())
            advance()
            continue
        if value == 59:
            while index < len(raw) and raw[index] not in (10, 13):
                advance()
            continue
        if value == 10:
            advance()
            if not depth:
                if tokens:
                    rows += 1
                    if rows > limits.records:
                        raise Gap("record_budget_exceeded", loc())
                    yield Row(tuple(tokens), omitted)
                tokens, omitted, start = [], False, True
            continue
        if value in (40, 41):
            depth += 1 if value == 40 else -1
            if depth < 0:
                raise Gap("unmatched_close_parenthesis", loc())
            if depth > limits.nesting:
                raise Gap("parenthesis_budget_exceeded", loc())
            advance()
            continue
        start = False
        token_location = loc()
        quoted = value == 34
        if quoted:
            advance()
        body = bytearray()
        closed = not quoted
        while index < len(raw):
            value = raw[index]
            if value == 92:
                body.append(value)
                advance()
                if index == len(raw) or raw[index] in (10, 13):
                    raise Gap("unsupported_escape_continuation", loc())
                if raw[index] >= 127 or raw[index] < 32:
                    raise Gap("unsupported_raw_character", loc())
                body.append(raw[index])
                advance()
            elif quoted and value == 34:
                advance()
                closed = True
                if index < len(raw) and raw[index] not in b" \t\r\n;()":
                    raise Gap("adjacent_quoted_token_unsupported", loc())
                break
            elif value in b" \t\r\n;()" and not quoted:
                break
            else:
                if value >= 127 or value < 32:
                    raise Gap("unsupported_raw_character", loc())
                if value == 34 and not quoted:
                    raise Gap("embedded_quote_unsupported", loc())
                body.append(value)
                advance()
            if len(body) > limits.token_bytes:
                raise Gap("token_byte_budget_exceeded", token_location)
        if not closed:
            raise Gap("unterminated_quoted_string", token_location)
        count += 1
        if count > limits.tokens:
            raise Gap("token_budget_exceeded", token_location)
        tokens.append(Token(bytes(body), quoted, token_location, depth))
    if depth:
        raise Gap("unclosed_parenthesis", Location(source, line, column, index))
    if tokens:
        rows += 1
        if rows > limits.records:
            raise Gap("record_budget_exceeded", tokens[0].location)
        yield Row(tuple(tokens), omitted)
