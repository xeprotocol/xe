@pytest.mark.asyncio
async def test_verify_fee_rejects_unfinalized():
    fee_acct = "ff" * 32
    author = "aa" * 32
    fee_hash = "bb" * 32
    unfinalized = {
        "hash": fee_hash,
        "type": "send",
        "asset": "XE",
        "destination": fee_acct,
        "account": author,
        "amount": 10_000_000,
        "finalized": False,
        "previous": "cc" * 32,
    }
    ctx = SimpleNamespace(
        signer=SimpleNamespace(has=lambda k: False),
        config=SimpleNamespace(accounts={"fee": fee_acct}),
        chain=FakeChain(unfinalized),
    )
    with pytest.raises(HTTPException) as exc_info:
        await _verify_fee(ctx, FakeDB(), fee_hash, author, fee=10_000_000)
    assert exc_info.value.status_code == 400
    assert "finalized" in exc_info.value.detail.lower()
