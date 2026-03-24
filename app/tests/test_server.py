"""
Fortress — Server Integration Tests
Run:  pytest tests/ -v
"""

import time
import base64
import json
import pytest
from datetime import timezone,timedelta,datetime

from app.crypto.keys import (
    generate_identity_keypair,
    generate_signed_prekey,
    generate_one_time_prekeys,
    encode_public_key,
    decode_public_key,
)
from app.crypto.x3dh import x3dh_sender, x3dh_receiver
from app.crypto.ratchet import (
    init_ratchet_sender,
    init_ratchet_receiver,
    ratchet_encrypt,
    ratchet_decrypt,
)
from app.crypto.sealed_sender import seal, unseal
from app.crypto.fingerprint import generate_safety_number


# ===========================================================================
# BLOCK 1 — Auth
# ===========================================================================

class TestAuth:

    def test_register_alice(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "username": "alice",
                "email": "alice@fortress.test",
                "password": "alice_secret_123",
            },
        )
        # 201 on first run; 400 if fixture already registered her — both fine
        assert resp.status_code in (201, 400)

    def test_register_bob(self, client, bob_auth):
        # bob_auth fixture handles registration; just assert id is present
        assert bob_auth["id"] > 0

    def test_duplicate_registration(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "username": "alice",
                "email": "alice2@fortress.test",
                "password": "doesnt_matter",
            },
        )
        assert resp.status_code == 400
        assert "already" in resp.json()["detail"].lower()

    def test_login_alice_returns_jwt(self, alice_auth):
        token = alice_auth["token"]
        assert isinstance(token, str)
        parts = token.split(".")
        assert len(parts) == 3, "JWT must have 3 dot-separated parts"

    def test_login_wrong_password(self, client):
        resp = client.post(
            "/auth/login",
            data={"username": "alice", "password": "WRONG"},
        )
        assert resp.status_code == 401

    def test_login_unknown_user(self, client):
        resp = client.post(
            "/auth/login",
            data={"username": "nobody", "password": "x"},
        )
        assert resp.status_code == 401

    def test_get_me(self, client, alice_auth):
        resp = client.get("/auth/me", headers=alice_auth["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "alice"
        assert "password" not in data
        assert "hashed_password" not in data

    def test_get_me_no_token(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_get_me_fake_token(self, client):
        resp = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer this.is.fake"},
        )
        assert resp.status_code == 401


# ===========================================================================
# BLOCK 2 — Key Bundles
# ===========================================================================

class TestKeyBundles:

    def test_upload_alice_keys(self, client, alice_auth, alice_keys):
        ik = alice_keys["identity"]
        spk = alice_keys["spk"]
        otpks = alice_keys["otpks"]

        payload = {
            "identity_key": encode_public_key(ik["dh_public"]),
            "signed_prekey": encode_public_key(spk["public"]),
            "signed_prekey_signature": encode_public_key(spk["signature"]),
            "prekey_id": 1,
            "one_time_prekeys": [encode_public_key(k["public"]) for k in otpks],
        }
        resp = client.post(
            "/keys/upload",
            json=payload,
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 201

    def test_upload_bob_keys(self, client, bob_auth, bob_keys):
        ik = bob_keys["identity"]
        spk = bob_keys["spk"]
        otpks = bob_keys["otpks"]

        payload = {
            "identity_key": encode_public_key(ik["dh_public"]),
            "signed_prekey": encode_public_key(spk["public"]),
            "signed_prekey_signature": encode_public_key(spk["signature"]),
            "prekey_id": 1,
            "one_time_prekeys": [encode_public_key(k["public"]) for k in otpks],
        }
        resp = client.post(
            "/keys/upload",
            json=payload,
            headers=bob_auth["headers"],
        )
        assert resp.status_code == 201

    def test_fetch_bob_bundle(self, client, alice_auth, bob_auth, bob_keys):
        resp = client.get(
            f"/keys/{bob_auth['id']}",
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["identity_key"] == encode_public_key(
            bob_keys["identity"]["dh_public"]
        )
        assert data["one_time_prekey"] is not None
        # verify it is valid base64
        decoded = base64.b64decode(data["one_time_prekey"])
        assert len(decoded) == 32

    def test_otp_key_consumed_on_each_fetch(self, client, alice_auth, bob_auth):
        resp1 = client.get(f"/keys/{bob_auth['id']}", headers=alice_auth["headers"])
        resp2 = client.get(f"/keys/{bob_auth['id']}", headers=alice_auth["headers"])
        otp1 = resp1.json().get("one_time_prekey")
        otp2 = resp2.json().get("one_time_prekey")
        # they should differ (or second could be None if pool exhausted)
        assert otp1 != otp2 or otp2 is None

    def test_fetch_nonexistent_bundle(self, client, alice_auth):
        resp = client.get("/keys/99999", headers=alice_auth["headers"])
        assert resp.status_code == 404


# ===========================================================================
# BLOCK 3 — Local Crypto (no HTTP)
# ===========================================================================

class TestLocalCrypto:

    def test_x3dh_shared_secret_matches(self, alice_keys, bob_keys):
        alice_result = x3dh_sender(
            ik_a_private=alice_keys["identity"]["dh_private"],
            ik_b_public=bob_keys["identity"]["dh_public"],
            spk_b_public=bob_keys["spk"]["public"],
            opk_b_public=bob_keys["otpks"][0]["public"],
        )
        bob_secret = x3dh_receiver(
            ik_b_private=bob_keys["identity"]["dh_private"],
            spk_b_private=bob_keys["spk"]["private"],
            ik_a_public=alice_keys["identity"]["dh_public"],
            ek_a_public=alice_result["ek_public"],
            opk_b_private=bob_keys["otpks"][0]["private"],
        )
        assert alice_result["shared_secret"] == bob_secret

    def test_ratchet_alice_to_bob(self, alice_keys, bob_keys):
        # derive shared secret
        alice_result = x3dh_sender(
            ik_a_private=alice_keys["identity"]["dh_private"],
            ik_b_public=bob_keys["identity"]["dh_public"],
            spk_b_public=bob_keys["spk"]["public"],
            opk_b_public=bob_keys["otpks"][1]["public"],
        )
        bob_secret = x3dh_receiver(
            ik_b_private=bob_keys["identity"]["dh_private"],
            spk_b_private=bob_keys["spk"]["private"],
            ik_a_public=alice_keys["identity"]["dh_public"],
            ek_a_public=alice_result["ek_public"],
            opk_b_private=bob_keys["otpks"][1]["private"],
        )

        bob_ratchet_kp = generate_identity_keypair()
        alice_state = init_ratchet_sender(
            alice_result["shared_secret"], bob_ratchet_kp["dh_public"]
        )
        bob_state = init_ratchet_receiver(
            bob_secret, bob_ratchet_kp["dh_private"]
        )

        messages = [b"hello bob", b"how are you", b"fortress works"]
        for plaintext in messages:
            header, ct = ratchet_encrypt(alice_state, plaintext)
            decrypted = ratchet_decrypt(bob_state, header, ct)
            assert decrypted == plaintext

    def test_ratchet_bidirectional(self, alice_keys, bob_keys):
        alice_result = x3dh_sender(
            ik_a_private=alice_keys["identity"]["dh_private"],
            ik_b_public=bob_keys["identity"]["dh_public"],
            spk_b_public=bob_keys["spk"]["public"],
            opk_b_public=bob_keys["otpks"][2]["public"],
        )
        bob_secret = x3dh_receiver(
            ik_b_private=bob_keys["identity"]["dh_private"],
            spk_b_private=bob_keys["spk"]["private"],
            ik_a_public=alice_keys["identity"]["dh_public"],
            ek_a_public=alice_result["ek_public"],
            opk_b_private=bob_keys["otpks"][2]["private"],
        )

        bob_ratchet_kp = generate_identity_keypair()
        alice_state = init_ratchet_sender(
            alice_result["shared_secret"], bob_ratchet_kp["dh_public"]
        )
        bob_state = init_ratchet_receiver(
            bob_secret, bob_ratchet_kp["dh_private"]
        )

        # alice → bob
        for i in range(3):
            h, ct = ratchet_encrypt(alice_state, f"alice msg {i}".encode())
            assert ratchet_decrypt(bob_state, h, ct) == f"alice msg {i}".encode()

        # bob → alice
        for i in range(3):
            h, ct = ratchet_encrypt(bob_state, f"bob reply {i}".encode())
            assert ratchet_decrypt(alice_state, h, ct) == f"bob reply {i}".encode()

    def test_sealed_sender_round_trip(self, alice_keys, bob_keys):
        sealed = seal(
            sender_id=1,
            sender_ik_public=alice_keys["identity"]["dh_public"],
            recipient_ik_public=bob_keys["identity"]["dh_public"],
            ciphertext=b"secret ciphertext payload",
            header={"dh_public": "abc123", "send_count": 1, "recv_count": 0},
        )
        result = unseal(bob_keys["identity"]["dh_private"], sealed)

        assert result["sender_id"] == 1
        assert base64.b64decode(result["ciphertext"]) == b"secret ciphertext payload"
        assert result["header"]["send_count"] == 1

    def test_sealed_sender_wrong_key_fails(self, alice_keys, bob_keys):
        sealed = seal(
            sender_id=1,
            sender_ik_public=alice_keys["identity"]["dh_public"],
            recipient_ik_public=bob_keys["identity"]["dh_public"],
            ciphertext=b"payload",
            header={},
        )
        wrong_key = generate_identity_keypair()
        with pytest.raises(Exception):
            unseal(wrong_key["dh_private"], sealed)

    def test_safety_numbers_symmetric(self, alice_keys, bob_keys):
        sn_alice = generate_safety_number(
            1,
            alice_keys["identity"]["dh_public"],
            2,
            bob_keys["identity"]["dh_public"],
        )
        sn_bob = generate_safety_number(
            2,
            bob_keys["identity"]["dh_public"],
            1,
            alice_keys["identity"]["dh_public"],
        )
        # generate_safety_number returns a string directly
        # extract safety_number if it returns a dict, otherwise compare directly
        sn_alice_val = sn_alice["safety_number"] if isinstance(sn_alice, dict) else sn_alice
        sn_bob_val   = sn_bob["safety_number"]   if isinstance(sn_bob,   dict) else sn_bob
        assert sn_alice_val == sn_bob_val, (
            f"Safety numbers must match regardless of perspective\n"
            f"  alice: {sn_alice_val}\n"
            f"  bob:   {sn_bob_val}"
        )

    def test_safety_number_changes_with_key(self, alice_keys, bob_keys):
        sn_original = generate_safety_number(
            1, alice_keys["identity"]["dh_public"],
            2, bob_keys["identity"]["dh_public"],
        )
        impostor = generate_identity_keypair()
        sn_tampered = generate_safety_number(
            1, alice_keys["identity"]["dh_public"],
            2, impostor["dh_public"],
        )
        assert sn_original != sn_tampered, "Tampered key must change safety number"


# ===========================================================================
# BLOCK 4 — Messaging
# ===========================================================================

class TestMessaging:

    def _make_sealed_blob(self, alice_keys, bob_keys, plaintext: bytes) -> str:
        """Helper: full X3DH + ratchet + seal pipeline, returns base64 string."""
        alice_result = x3dh_sender(
            ik_a_private=alice_keys["identity"]["dh_private"],
            ik_b_public=bob_keys["identity"]["dh_public"],
            spk_b_public=bob_keys["spk"]["public"],
            opk_b_public=bob_keys["otpks"][3]["public"],
        )
        bob_ratchet_kp = generate_identity_keypair()
        alice_state = init_ratchet_sender(
            alice_result["shared_secret"], bob_ratchet_kp["dh_public"]
        )
        header, ct = ratchet_encrypt(alice_state, plaintext)
        sealed = seal(
            sender_id=1,
            sender_ik_public=alice_keys["identity"]["dh_public"],
            recipient_ik_public=bob_keys["identity"]["dh_public"],
            ciphertext=ct,
            header=header,
        )
        return base64.b64encode(sealed).decode()

    def test_send_message(self, client, alice_auth, bob_auth, alice_keys, bob_keys):
        sealed_blob = self._make_sealed_blob(alice_keys, bob_keys, b"hello fortress")
        resp = client.post(
            "/messages/send",
            json={
                "recipient_id": bob_auth["id"],
                "sealed_blob": sealed_blob,
                "message_number": 1,
            },
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["recipient_id"] == bob_auth["id"]
        assert "sender_id" not in data  # sealed sender — server must not store it
        assert "plaintext" not in data

    def test_inbox_has_message(self, client, bob_auth):
        resp = client.get("/messages/inbox", headers=bob_auth["headers"])
        assert resp.status_code == 200
        messages = resp.json()
        assert len(messages) >= 1
        msg = messages[0]
        assert "sealed_blob" in msg
        assert "plaintext" not in msg
        assert "sender_id" not in msg

    def test_confirm_delivery_removes_message(self, client, bob_auth):
        # get first message
        inbox = client.get("/messages/inbox", headers=bob_auth["headers"]).json()
        message_id = inbox[0]["id"]

        # confirm it
        resp = client.delete(
            f"/messages/{message_id}/confirm",
            headers=bob_auth["headers"],
        )
        assert resp.status_code == 200

        # inbox should no longer contain it
        inbox_after = client.get("/messages/inbox", headers=bob_auth["headers"]).json()
        ids_after = [m["id"] for m in inbox_after]
        assert message_id not in ids_after

    def test_cannot_confirm_others_message(
        self, client, alice_auth, bob_auth, alice_keys, bob_keys
    ):
        # alice sends another message
        sealed_blob = self._make_sealed_blob(alice_keys, bob_keys, b"second message")
        send_resp = client.post(
            "/messages/send",
            json={
                "recipient_id": bob_auth["id"],
                "sealed_blob": sealed_blob,
                "message_number": 2,
            },
            headers=alice_auth["headers"],
        )
        message_id = send_resp.json()["id"]

        # alice tries to confirm bob's message → should fail
        resp = client.delete(
            f"/messages/{message_id}/confirm",
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 403

    def test_send_to_nonexistent_recipient(self, client, alice_auth):
        resp = client.post(
            "/messages/send",
            json={
                "recipient_id": 99999,
                "sealed_blob": base64.b64encode(b"x" * 50).decode(),
                "message_number": 1,
            },
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 404

    def test_disappearing_message_created_with_expiry(
        self, client, alice_auth, bob_auth, alice_keys, bob_keys, db_session
    ):
        from app.models.message import Message

        sealed_blob = self._make_sealed_blob(alice_keys, bob_keys, b"disappear soon")
        resp = client.post(
            "/messages/send",
            json={
                "recipient_id": bob_auth["id"],
                "sealed_blob": sealed_blob,
                "message_number": 3,
                "ttl_seconds": 5,
            },
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 201
        message_id = resp.json()["id"]

        msg = db_session.query(Message).filter(Message.id == message_id).first()
        assert msg is not None
        assert msg.expires_at is not None

    def test_disappearing_message_purged_after_ttl(
        self, client, alice_auth, bob_auth, alice_keys, bob_keys
    ):
        sealed_blob = self._make_sealed_blob(alice_keys, bob_keys, b"gone in 5s")
        resp = client.post(
            "/messages/send",
            json={
                "recipient_id": bob_auth["id"],
                "sealed_blob": sealed_blob,
                "message_number": 4,
                "ttl_seconds": 2, # Shorter TTL for faster tests
            },
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 201
        message_id = resp.json()["id"]

        # 1. Wait for TTL to expire
        import time
        time.sleep(2) 

        # 2. Manual Purge
        from app.services.message_service import purge_expired_messages
        from app.database import SessionLocal

        db = SessionLocal()
        try:
            # Add a commit here just in case to ensure we're starting fresh
            db.commit() 
            deleted_count = purge_expired_messages(db)
            # LOG THIS: If this is 0, the query logic is the problem
            print(f"\nDELETED COUNT: {deleted_count}") 
        finally:
            db.close()

        # 3. Fetch inbox AGAIN
        # Ensure the test client isn't reusing a cached response
        resp = client.get("/messages/inbox", headers=bob_auth["headers"])
        inbox = resp.json()
        ids = [m["id"] for m in inbox]
        
        assert message_id not in ids


# ===========================================================================
# BLOCK 5 — Safety Numbers via API
# ===========================================================================

class TestSafetyNumbers:

    def test_safety_numbers_endpoint(self, client, alice_auth, bob_auth):
        resp = client.get(
            f"/safety/numbers/{bob_auth['id']}",
            headers=alice_auth["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "safety_number" in data
        assert "your_fingerprint" in data
        assert "their_fingerprint" in data

        # safety number should be space-separated 5-digit groups
        parts = data["safety_number"].split(" ")
        assert len(parts) == 6
        for part in parts:
            assert len(part) == 5
            assert part.isdigit()

    def test_safety_numbers_are_symmetric(
        self, client, alice_auth, bob_auth, alice_id
    ):
        sn_alice = client.get(
            f"/safety/numbers/{bob_auth['id']}",
            headers=alice_auth["headers"],
        ).json()["safety_number"]

        sn_bob = client.get(
            f"/safety/numbers/{alice_id}",
            headers=bob_auth["headers"],
        ).json()["safety_number"]

        assert sn_alice == sn_bob, (
            f"Safety numbers must match:\n  alice sees: {sn_alice}\n  bob sees:   {sn_bob}"
        )

    def test_safety_numbers_nonexistent_user(self, client, alice_auth):
        resp = client.get("/safety/numbers/99999", headers=alice_auth["headers"])
        assert resp.status_code == 404


# ===========================================================================
# BLOCK 6 — Security Headers & Rate Limiting
# ===========================================================================

class TestSecurity:

    def test_security_headers_present(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Server") == "Fortress"
        assert resp.headers.get("Cache-Control") == "no-store"
        assert resp.headers.get("X-XSS-Protection") is not None

    def test_server_header_hides_framework(self, client):
        resp = client.get("/")
        server = resp.headers.get("Server", "")
        assert "uvicorn" not in server.lower()
        assert "python" not in server.lower()

    def test_rate_limit_triggers_on_login(self, client):
        """Send rapid login attempts — expect at least one 429."""
        statuses = []
        for _ in range(15):
            r = client.post(
                "/auth/login",
                data={"username": "alice", "password": "wrong"},
            )
            statuses.append(r.status_code)

        assert 429 in statuses, (
            f"Expected at least one 429 in {statuses}\n"
            f"Check that rate limiter is wired to the /auth/login route."
        )

    def test_unauthenticated_routes_blocked(self, client):
        protected = [
            ("GET",  "/auth/me"),
            ("POST", "/messages/send"),
            ("GET",  "/messages/inbox"),
            ("POST", "/keys/upload"),
        ]
        for method, path in protected:
            if method == "GET":
                resp = client.get(path)
            else:
                resp = client.post(path, json={})
            assert resp.status_code in (401, 422), (
                f"{method} {path} should be protected, got {resp.status_code}"
            )