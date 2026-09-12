from decimal import ROUND_HALF_UP, Decimal

#: One place where rounding happens. Money is NUMERIC(12,2) in Postgres and
#: Decimal in Python — never float, at any point, including in tests.
CENTS = Decimal("0.01")


def money(value: Decimal | int | str) -> Decimal:
    """Normalize any monetary value to exactly two decimal places."""
    return Decimal(value).quantize(CENTS, rounding=ROUND_HALF_UP)


def total(amounts: list[Decimal]) -> Decimal:
    return money(sum(amounts, Decimal("0")))


def format_money(value: Decimal, currency: str) -> str:
    return f"{money(value)} {currency}"
