"""What may be said about a failure where the public can read it."""

from __future__ import annotations

from fastapi import HTTPException

from xe.chat import ChatError
from xe.client import XeError
from xe.directory import DirectoryError
from xe.encoding import EncodingError
from xe.keys import KeyError_
from xe.statechain import StateChainError

from .log import LogError
from .signer import SignerError


class Fault(RuntimeError):
    """A failure this service states in its own words, for whoever reads the row or the log entry it ends up
    on. Raised where the code has something to tell an operator and no narrower type to tell it with: a bare
    RuntimeError's text is not kept (`reason`), because most of them are not ours."""


# Failures whose message this code or the protocol package wrote: the node's answer as the client words
# it, a refused key, signature, block, op, keyset or envelope, the signer saying what it does not hold, the
# log saying it could not be written, and what the service raises as its own (`Fault`). The client words a
# refusal from its status; what the node sent with it is on the error as `said`, for the server's log,
# and is in none of these messages (XE-14195).
WORDED = (XeError, StateChainError, KeyError_, EncodingError, ChatError, DirectoryError, SignerError, LogError, Fault)


def worded(e: BaseException) -> bool:
    return isinstance(e, (HTTPException, *WORDED))


def reason(e: BaseException, limit: int = 300) -> str:
    """The words for a failure in a response, on a row a public route returns, or in an entry on the log:
    its own message if this code wrote it (`WORDED`, or a refusal this service raised), and otherwise the
    kind of failure and no more. The text of anything else is for the server's log, which the caller
    writes: a database driver's error names its host and its statement, an interpreter's quotes the value
    it choked on (XE-6983)."""
    if isinstance(e, HTTPException):
        return str(e.detail)[:limit]
    if isinstance(e, WORDED):
        return str(e)[:limit]
    return type(e).__name__
