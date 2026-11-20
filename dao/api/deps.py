from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..context import Context, get_context
from ..db import get_db

Ctx = Annotated[Context, Depends(get_context)]
Db = Annotated[AsyncSession, Depends(get_db)]
