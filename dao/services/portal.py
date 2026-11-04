from __future__ import annotations

import logging
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

async def _verify_fee(ctx, db, fee_hash: str, author: str, fee: int) -> dict:
    block = await ctx.chain.block(fee_hash)
    if not block:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fee block not found")
    
    if block.get("type") != "send":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fee block must be a send")
    
    if block.get("asset") != "XE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fee asset must be XE")
    
    if block.get("destination") != ctx.config.accounts.get("fee"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fee destination")
        
    if block.get("account") != author:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fee block account must match author")
        
    if block.get(
        "amount"
    ) < fee:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient fee amount")
        
    if not block.get("finalized", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fee block must be finalized")
        
    return block
