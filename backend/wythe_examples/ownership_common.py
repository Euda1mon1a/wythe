"""Synthetic identities and records for in-process ownership regression tests only."""

from dataclasses import dataclass

from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "example_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int]
    title: Mapped[str]


@dataclass(frozen=True)
class User:
    id: int


class RecordUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str


def get_user(authorization: str | None = Header(default=None)) -> User:
    """Fixed PUBLIC fixture tokens, not an example of production authentication."""
    identities = {"Bearer demo-user-1": 1, "Bearer demo-user-2": 2}
    if authorization not in identities:
        raise HTTPException(status_code=401, detail="Unknown synthetic user")
    return User(id=identities[authorization])


def get_session():
    raise RuntimeError("Only the in-process example harness supplies a database")
