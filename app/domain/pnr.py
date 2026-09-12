import secrets

#: Airline record locators avoid characters that get misread over a phone or in
#: handwriting: no 0/O, no 1/I, no 8/B ambiguity source, no vowels that could
#: spell something unfortunate.
PNR_ALPHABET = "23456789ACDEFGHJKLMNPQRSTUVWXYZ"
PNR_LENGTH = 6

E_TICKET_PREFIX = "014"  # IATA-style 3-digit airline code prefix, then 10 digits


def generate_pnr() -> str:
    return "".join(secrets.choice(PNR_ALPHABET) for _ in range(PNR_LENGTH))


def generate_eticket_number() -> str:
    digits = "".join(secrets.choice("0123456789") for _ in range(10))
    return f"{E_TICKET_PREFIX}{digits}"
