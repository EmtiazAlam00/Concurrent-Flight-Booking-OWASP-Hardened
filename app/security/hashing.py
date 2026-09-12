import contextlib
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import settings

#: Tuned so a single verify costs ~50-100ms on commodity hardware. That cost is
#: the point: it is what makes an offline crack of a stolen dump expensive.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

#: Verifying this on a miss keeps login timing roughly constant whether or not
#: the email exists, so the endpoint isn't a user-enumeration oracle.
_DUMMY_HASH = _hasher.hash("skylock-timing-equalizer")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        # No such user. Burn the same CPU anyway before returning False.
        with contextlib.suppress(VerifyMismatchError, VerificationError, InvalidHashError):
            _hasher.verify(_DUMMY_HASH, password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used weaker parameters than we now require."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def normalize_email(email: str) -> str:
    return email.strip().lower()


# --- opaque token material --------------------------------------------------


def new_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def card_fingerprint(card_token: str) -> str:
    """Stable pseudonymous id for a card, derived with a server-side key.

    Lets velocity rules ask "has this card been tried on other accounts?"
    without the fingerprint being reversible or correlatable by anyone who only
    sees the database.
    """
    return hmac.new(settings.jwt_secret.encode(), card_token.encode(), hashlib.sha256).hexdigest()[
        :32
    ]
