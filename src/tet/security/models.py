from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from tet.security.config import MultiFactorAuthMethodType, UTC


class MultiFactorAuthenticationMethodMixin:
    """
    Mixin to store and manage a user's multi-factor authentication method.

    Attributes:
        id (int): Primary key for the Multi-factor authentication record.
        method_type (MultiFactorAuthMethodType): Enum indicating the type of 2FA method (e.g. TOTP, U2F, etc.).
        data (dict): JSONB field holding method-specific configuration or secret data.
        is_active (bool): Flag indicating if the 2FA method is currently enabled.
        verified (bool): Flag indicating if the 2FA method has been verified for the user.
        created_at (datetime): Time when the record was created (timezone-aware).
        last_used_at (datetime, optional): Timestamp of the most recent use of the 2FA method.
    """

    __tablename__ = "multi_factor_authentication_method"
    id: Mapped[int] = mapped_column(primary_key=True)
    method_type: Mapped[MultiFactorAuthMethodType] = mapped_column(
        Enum(MultiFactorAuthMethodType, values_callable=lambda cls: [e.value for e in cls]),
        index=True,
    )
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(default=False)
    verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(True), default=lambda: datetime.now(UTC)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(True))

    def mark_used(self):
        self.last_used_at = datetime.now(UTC)


class TOTPReplayStateMixin:
    """
    Per-user replay-protection state for TOTP: a single high-water-mark row
    holding the most recent time-step accepted for the user.  A code is rejected
    when its time-step is less than or equal to ``last_used_time_step``.

    Unlike a used-code history, this stores **one row per user** (updated in
    place), so it never grows and needs no periodic cleanup.

    The mixin owns the primary key: ``user_id`` is a foreign key declared
    ``primary_key=True``, so there is exactly one row per user by construction.
    The application only supplies the foreign-key target (the user table's PK
    name varies per app) via ``__user_id_fk__`` and marks the table
    ``UNLOGGED`` -- ephemeral state that is safe to lose on a crash, kept out of
    the write-ahead log so it adds no WAL traffic on the login path::

        class TOTPReplayState(TOTPReplayStateMixin, Base):
            __user_id_fk__ = "users.id"
            __table_args__ = {"prefixes": ["UNLOGGED"]}
    """

    __tablename__ = "totp_replay_state"

    #: Application-supplied target of the ``user_id`` foreign key, e.g.
    #: ``"users.id"``.  It cannot be hardcoded here because the user table name
    #: is application-specific.
    __user_id_fk__ = None

    @declared_attr
    def user_id(cls) -> Mapped[int]:
        if not cls.__user_id_fk__:
            raise TypeError(
                f"{cls.__name__}: set __user_id_fk__ to the user primary key to "
                'reference, e.g. __user_id_fk__ = "users.id"'
            )
        return mapped_column(ForeignKey(cls.__user_id_fk__), primary_key=True)

    last_used_time_step: Mapped[int] = mapped_column(BigInteger)


class RateLimitAttemptMixin:
    """
    Records individual rate-limited attempts keyed by an arbitrary string.

    The table should be created as ``UNLOGGED``
    (``__table_args__ = {'prefixes': ['UNLOGGED']}``).
    """

    __tablename__ = "rate_limit_attempt"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(True), default=lambda: datetime.now(UTC)
    )


class TokenMixin:
    """
    Stores long-term tokens for users with creation and optional expiration timestamps.

    User ID foreign key needs to be provided by the application.


    **Attributes:**

    * ``id:`` Primary key for the token.
    * ``secret_hash:`` The SHA-256 hashed secret.
    * ``created_at:`` Timestamp when the token was created.
    * ``expires_at:`` Optional timestamp for token expiration.

    """

    __tablename__ = "tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    secret_hash: Mapped[str] = mapped_column()
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(True), default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(True))
