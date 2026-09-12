"""Authentication hardening: rotation, replay detection, lockout, enumeration."""

import pytest
from sqlalchemy import func, select

from app.config import settings
from app.domain.enums import SecurityEventType
from app.domain.models import RefreshToken, SecurityEvent, User
from tests.conftest import STRONG_PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.integration]


class TestRefreshRotation:
    async def test_rotation_issues_a_new_token_and_retires_the_old(self, client, user, db):
        response = await client.post("/auth/refresh", json={"refresh_token": user.refresh})
        assert response.status_code == 200

        rotated = response.json()["refresh_token"]
        assert rotated != user.refresh

        # The old token is marked used, not deleted — the sentinel is what makes
        # replay detectable at all.
        from app.security.hashing import sha256_hex

        old = await db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(user.refresh))
        )
        assert old.used_at is not None

    async def test_a_rotation_chain_works(self, client, user):
        token = user.refresh
        for _ in range(4):
            response = await client.post("/auth/refresh", json={"refresh_token": token})
            assert response.status_code == 200
            token = response.json()["refresh_token"]

    async def test_the_new_access_token_actually_works(self, client, user):
        rotated = (await client.post("/auth/refresh", json={"refresh_token": user.refresh})).json()
        response = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {rotated['access_token']}"}
        )
        assert response.status_code == 200


class TestRefreshReuseDetection:
    async def test_replaying_a_rotated_token_kills_the_whole_family(self, client, user, db):
        """The headline auth behaviour.

        Presenting an already-used refresh token means either theft or a buggy
        client, and we cannot tell which — so we assume theft. The legitimate
        user re-authenticates once; an attacker holding a stolen token loses the
        session entirely.
        """
        first = (await client.post("/auth/refresh", json={"refresh_token": user.refresh})).json()[
            "refresh_token"
        ]

        replay = await client.post("/auth/refresh", json={"refresh_token": user.refresh})
        assert replay.status_code == 401
        assert replay.json()["code"] == "token_reuse_detected"

        # The child issued by the legitimate rotation is dead too. That is the
        # point: the attacker's token and the victim's token are in the same
        # family and we cannot tell them apart.
        after = await client.post("/auth/refresh", json={"refresh_token": first})
        assert after.status_code == 401
        assert after.json()["code"] == "invalid_token"

        revoked = await db.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_not(None))
        )
        assert revoked >= 2

    async def test_reuse_is_logged_at_high_severity(self, client, user, db):
        await client.post("/auth/refresh", json={"refresh_token": user.refresh})
        await client.post("/auth/refresh", json={"refresh_token": user.refresh})

        event = await db.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == SecurityEventType.REFRESH_REUSE_DETECTED,
                SecurityEvent.actor_user_id == user.id,
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.severity == "high"
        assert event.decision == "revoke_family"
        assert event.detail["tokens_revoked"] >= 1

    async def test_the_user_can_still_log_in_again(self, client, user):
        """Revoking the family must not lock the legitimate user out for good."""
        await client.post("/auth/refresh", json={"refresh_token": user.refresh})
        await client.post("/auth/refresh", json={"refresh_token": user.refresh})

        response = await client.post(
            "/auth/login", json={"email": user.email, "password": STRONG_PASSWORD}
        )
        assert response.status_code == 200

    async def test_an_unknown_token_is_rejected_without_a_500(self, client):
        response = await client.post(
            "/auth/refresh", json={"refresh_token": "not-a-real-token-value-at-all"}
        )
        assert response.status_code == 401
        assert response.json()["code"] == "invalid_token"


class TestLogout:
    async def test_logout_revokes_the_family_not_just_the_token(self, client, user):
        rotated = (await client.post("/auth/refresh", json={"refresh_token": user.refresh})).json()[
            "refresh_token"
        ]

        assert (
            await client.post("/auth/logout", json={"refresh_token": rotated})
        ).status_code == 204
        assert (
            await client.post("/auth/refresh", json={"refresh_token": rotated})
        ).status_code == 401

    async def test_logout_of_an_unknown_token_still_returns_204(self, client):
        # Whether a token existed is not the caller's business.
        response = await client.post(
            "/auth/logout", json={"refresh_token": "some-token-that-never-existed"}
        )
        assert response.status_code == 204


class TestBruteForceLockout:
    async def test_the_account_locks_after_repeated_failures(self, client, make_user, db):
        user = await make_user()

        for _ in range(settings.login_max_failures):
            response = await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )
            assert response.status_code == 401

        # Even the correct password is refused while locked.
        locked = await client.post(
            "/auth/login", json={"email": user.email, "password": STRONG_PASSWORD}
        )
        assert locked.status_code == 423
        assert locked.json()["code"] == "account_locked"

        row = await db.scalar(select(User).where(User.id == user.id))
        await db.refresh(row)
        assert row.locked_until is not None

    async def test_a_successful_login_resets_the_counter(self, client, make_user, db):
        user = await make_user()
        for _ in range(settings.login_max_failures - 1):
            await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )

        assert (
            await client.post(
                "/auth/login", json={"email": user.email, "password": STRONG_PASSWORD}
            )
        ).status_code == 200

        row = await db.scalar(select(User).where(User.id == user.id))
        await db.refresh(row)
        assert row.failed_login_count == 0
        assert row.locked_until is None

    async def test_lockout_is_recorded(self, client, make_user, db):
        user = await make_user()
        for _ in range(settings.login_max_failures):
            await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )

        event = await db.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == SecurityEventType.ACCOUNT_LOCKED,
                SecurityEvent.actor_user_id == user.id,
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None and event.severity == "high"


class TestUserEnumeration:
    async def test_unknown_and_wrong_password_are_indistinguishable(self, client, make_user):
        user = await make_user()

        unknown = await client.post(
            "/auth/login",
            json={"email": "definitely-not-registered@example.com", "password": "x" * 20},
        )
        wrong = await client.post(
            "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
        )

        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json()["code"] == wrong.json()["code"] == "invalid_credentials"
        assert unknown.json()["detail"] == wrong.json()["detail"]


class TestPasswordPolicy:
    @pytest.mark.parametrize("password", ["short", "elevenchars", "password1234"])
    async def test_weak_passwords_are_rejected(self, client, password):
        response = await client.post(
            "/auth/register", json={"email": "weak@example.com", "password": password}
        )
        assert response.status_code == 422

    async def test_duplicate_registration_is_a_409(self, client, user):
        response = await client.post(
            "/auth/register", json={"email": user.email, "password": STRONG_PASSWORD}
        )
        assert response.status_code == 409
        assert response.json()["code"] == "email_already_registered"

    async def test_email_is_case_insensitive(self, client, user):
        response = await client.post(
            "/auth/login", json={"email": user.email.upper(), "password": STRONG_PASSWORD}
        )
        assert response.status_code == 200

    async def test_the_password_is_never_echoed_back(self, client):
        response = await client.post(
            "/auth/register",
            json={"email": "echo-check@example.com", "password": "a-very-secret-password"},
        )
        assert "a-very-secret-password" not in response.text


class TestTokenValidation:
    async def test_a_tampered_signature_is_rejected(self, client, user):
        tampered = user.access[:-4] + ("aaaa" if not user.access.endswith("aaaa") else "bbbb")
        response = await client.get("/auth/me", headers={"Authorization": f"Bearer {tampered}"})
        assert response.status_code == 401

    async def test_the_none_algorithm_is_not_accepted(self, client, user):
        """alg=none is the classic JWT bypass; PyJWT is told the algorithm."""
        import base64
        import json

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        claims = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": str(user.id),
                    "typ": "access",
                    "exp": 9999999999,
                    "iat": 1,
                    "iss": "skylock",
                    "aud": "skylock-api",
                }
            ).encode()
        ).rstrip(b"=")
        forged = f"{header.decode()}.{claims.decode()}."

        response = await client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == 401

    async def test_missing_bearer_is_401(self, client):
        assert (await client.get("/auth/me")).status_code == 401
