from tet.security.authentication import (
    TokenMixin,
    MultiFactorAuthenticationMethodMixin,
    TOTPReplayStateMixin,
    RateLimitAttemptMixin,
)
from tet.sqlalchemy.password import UserPasswordMixin

from sqlalchemy import ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, relationship
from sqlalchemy.schema import MetaData

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)
Base = declarative_base(metadata=metadata)


class User(UserPasswordMixin, Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    display_name: Mapped[str] = mapped_column(Text, default="")
    is_admin: Mapped[bool] = mapped_column(default=False, server_default="false")


class Token(TokenMixin, Base):
    __tablename__ = "token"
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    user: Mapped[User] = relationship(backref="tokens")


class MultiFactorAuthenticationMethod(MultiFactorAuthenticationMethodMixin, Base):
    __tablename__ = "multi_factor_authentication_method"
    user_id: Mapped[int] = mapped_column(ForeignKey(User.id))
    user: Mapped[User] = relationship(backref="multi_factor_authentication_methods")

    # Unique constraint on (user_id, method_type)
    __table_args__ = (
        UniqueConstraint("user_id", "method_type", name="unique_mfa_method_type_per_user"),
    )


class TOTPReplayState(TOTPReplayStateMixin, Base):
    __user_id_fk__ = "user.id"
    __table_args__ = {"prefixes": ["UNLOGGED"]}


class RateLimitAttempt(RateLimitAttemptMixin, Base):
    __tablename__ = "rate_limit_attempt"
    __table_args__ = {"prefixes": ["UNLOGGED"]}


__all__ = ["User", "Token", "Base", "metadata", "TOTPReplayState", "RateLimitAttempt"]
