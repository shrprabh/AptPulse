from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from models import GroupRole


class MemberOut(BaseModel):
    user_id: int
    display_name: Optional[str] = None
    role: GroupRole
    joined_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


class MemberUpdateIn(BaseModel):
    role: Optional[GroupRole] = None
    is_active: Optional[bool] = None
