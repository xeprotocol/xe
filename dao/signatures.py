"""Member signatures kept on a record: a resolution, a pause extension, a pause lift.

One rule, read and written here so the count and the gate cannot disagree: a stored signature counts when
its seat is entitled now and it was made with the key that seat holds today. A seat that has left carries
nothing (XE-0600, XE-0646); so does a key the seat has rotated away from, exactly as a session counts
approvals against the live keyset (XE-1761). A seat whose stored signature no longer counts is a seat
that has not signed: it may sign again, and the new signature replaces the one set aside (XE-1966). The
first version of this rule lived in three places as "the list holds this seat id", which refused the
re-signature the count was waiting for.
"""

from __future__ import annotations

from fastapi import HTTPException


def counting(seats: dict[str, str], sigs: list[dict]) -> tuple[list[dict], list[str]]:
    """`seats` is {seat id: public key} for the seats entitled to sign now. Returns the signatures that
    count and the seat ids whose stored signature was set aside."""
    live = [s for s in sigs if seats.get(s["seat"]) and seats[s["seat"]] == (s.get("public_key") or "").lower()]
    set_aside = sorted({s["seat"] for s in sigs} - {s["seat"] for s in live})
    return live, set_aside


def add(seats: dict[str, str], sigs: list[dict], entry: dict, refusal: str) -> list[dict]:
    """The list with `entry` added. Refused (409) only when the seat already holds a signature that counts;
    one that was set aside is replaced, so a list never carries two entries for a seat."""
    live, _ = counting(seats, sigs)
    if any(s["seat"] == entry["seat"] for s in live):
        raise HTTPException(409, refusal)
    return [*(s for s in sigs if s["seat"] != entry["seat"]), entry]
