import dataclasses
import hashlib
import logging
import secrets
import typing as tp
from datetime import datetime, timedelta, timezone

import jwt
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.authorization import ACLHelper
from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPForbidden, HTTPUnauthorized
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import Request, Response
from pyramid.security import NO_PERMISSION_REQUIRED, Everyone, Authenticated
from pyramid_di import RequestScopedBaseService, autowired
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import Session
from zope.interface import Interface, implementer

logger = logging.getLogger(__name__)
__all__ = [
    "TokenAuthenticationPolicy",
    "JWTCookieAuthenticationPolicy",
    "TokenMixin",
    "JWTRegisteredClaims",
]


@dataclasses.dataclass
class JWTRegisteredClaims:
    """
    A dataclass representing the registered claims in a JSON Web Token (JWT).

    These claims are defined by the JWT specification (RFC 7519) and are commonly
    used for token validation. The fields are optional and can be included as needed.

    More info about the registered claims can be found here:
        https://pyjwt.readthedocs.io/en/2.0.1/usage.html?highlight=datetime#registered-claim-names

    Attributes:
        user_id (Any): User ID - The unique identifier for the user.
        iss (str): Issuer - Identifies the principal that issued the JWT.
        sub (str): Subject - Identifies the principal that is the subject of the JWT.
        aud (Union[str, list]): Audience - Identifies the recipients that the JWT is intended for.
        exp (datetime): Expiration Time - Identifies when the JWT expires.
        nbf (datetime): Not Before - Identifies when the JWT becomes valid.
        iat (datetime): Issued At - Identifies when the JWT was issued.
        jti (str): JWT ID - A unique identifier for the JWT.
        leeway (int): The amount of time (in seconds) that the token is valid before/after the specified time.

    Methods:
        to_dict() -> dict[str, Any]:
            Converts the dataclass instance into a dictionary

    Example:

        .. code-block:: python

            claims = JWTRegisteredClaims(
                iss="my-auth-service",
                sub="user123",
                aud="my-api.example.com",
                exp=datetime.utcnow() + timedelta(hours=1),
                iat=datetime.utcnow(),
                jti="unique-token-id-456"
            )

            payload = claims.to_dict()
    """

    user_id: tp.Any = None
    iss: str = None
    sub: str = None
    aud: tp.Union[str, list] = None
    exp: datetime = None
    nbf: datetime = None
    iat: datetime = None
    jti: str = None
    leeway: int = 0

    def to_dict(self) -> tp.Dict[str, tp.Any]:
        """
        Converts the JWTRegisteredClaims instance into a dictionary.

        Ensures that datetime fields (`exp`, `nbf`, `iat`) are represented
        as Unix timestamps (seconds since epoch) or datetime objects.

        Returns:
            dict[str, Any]: A dictionary representation of the registered claims.
        """
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


@implementer(ISecurityPolicy)
class TokenAuthenticationPolicy(CallbackAuthenticationPolicy):
    """
    A Pyramid security policy for token-based authentication.

    All methods in this class are only invoked if the view has a `permission` set in `@view_config()`.
    This ensures that authentication and authorization checks are enforced before access is granted.

    Example:

    .. code-block:: python

        @view_config(route_name="home", renderer="json", permission="view")
        def home_view(request):
            user_id = request.authenticated_userid
            return {"message": f"Hello, User {user_id}"}
    """

    def __init__(self):
        self.acl = ACLHelper()

    def authenticated_userid(self, request: Request) -> tp.Optional[int]:
        """This method of the policy should
        only return a value if the request has been successfully authenticated.

        Returns:
           - Return the ``userid`` of the currently authenticated user
           - ``None`` if no user is authenticated.
        """
        token_service: TetTokenService = request.find_service(TetTokenService)
        jwt_token = request.headers.get(request.registry.tet_auth_access_token_header)

        if not jwt_token:
            return None

        payload = token_service.verify_jwt(jwt_token)

        return payload.get("user_id") if payload else None

    def permits(self, request, context, permission):
        principals = self.effective_principals(request)
        return self.acl.permits(context, principals, permission)

    def effective_principals(self, request) -> tp.List[str]:
        """This method of the policy should return at least one principal
        in the list: the userid of the user (and usually 'system.Authenticated'
        as well).
        Returns:
           A sequence representing the groups that the current user is in
        """
        principals = [Everyone]
        user_id = self.authenticated_userid(request)
        if user_id is not None:
            principals.extend([f"user:{user_id}", Authenticated])
        return principals

    def forget(self, request) -> tp.List[tuple[str, str]]:
        """
        This method does not need to be implemented for header-based authentication.
        """
        return []


@implementer(ISecurityPolicy)
class JWTCookieAuthenticationPolicy(TokenAuthenticationPolicy):
    """
    A Pyramid security policy that authenticates users via JWT tokens stored in cookies.

    All methods in this class are only invoked if the view has a `permission` set in `@view_config()`,
    ensuring authentication and authorization checks are enforced before access is granted.

    This policy retrieves JWT tokens from cookies instead of headers.
    """

    def __init__(self):
        super().__init__()

    def authenticated_userid(self, request: Request) -> tp.Optional[int]:
        token_service: TetTokenService = request.find_service(TetTokenService)
        access_token_cookie_name = request.registry.tet_auth_access_token_cookie_name
        jwt_token = request.cookies.get(access_token_cookie_name)

        if not jwt_token:
            return None

        payload = token_service.verify_jwt(jwt_token)
        return payload.get("user_id") if payload else None


DEFAULT_JWT_ALGORITHM = "HS256"
DEFAULT_JWT_TOKEN_EXPIRATION_MINS = 15
DEFAULT_USER_ID_COLUMN = "user_id"
DEFAULT_LONG_TERM_TOKEN_NAME = "X-Long-Token"
DEFAULT_ACCESS_TOKEN_NAME = "X-Access-Token"
DEFAULT_ACCESS_TOKEN_COOKIE_NAME = "access-token"
DEFAULT_REFRESH_TOKEN_COOKIE_NAME = "refresh-token"

DEFAULT_LOGIN_VIEW = "login"
COOKIE_LOGIN_VIEW = "cookie_login"
DEFAULT_REGISTERED_CLAIMS = JWTRegisteredClaims()
DEFAULT_SECURITY_POLICY = TokenAuthenticationPolicy()
UTC = timezone.utc


class ILoginCallback(tp.Protocol):
    """
    Authenticates a user and returns the user_id.

    **Returns:** ``user_id``
    """

    def __call__(self, request: Request) -> tp.Optional[tp.Any]:
        pass


class ISecretCallback(tp.Protocol):
    """
    **Returns:** The secret key for JWT
    """

    def __call__(self, request: Request) -> tp.Union[str, dict]:
        pass


def set_token_authentication(
    config: Configurator,
    *,
    long_term_token_model: tp.Any,
    project_prefix: str,
    login_callback: ILoginCallback,
    jwk_resolver: ISecretCallback,
    user_id_column: str = DEFAULT_USER_ID_COLUMN,
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
    jwt_token_expiration_mins: int = DEFAULT_JWT_TOKEN_EXPIRATION_MINS,
    access_token_header: str = DEFAULT_ACCESS_TOKEN_NAME,
    long_term_token_header: str = DEFAULT_LONG_TERM_TOKEN_NAME,
    access_token_cookie_name: str = DEFAULT_ACCESS_TOKEN_COOKIE_NAME,
    long_term_token_cookie_name: str = DEFAULT_REFRESH_TOKEN_COOKIE_NAME,
    default_claims: JWTRegisteredClaims = DEFAULT_REGISTERED_CLAIMS,
    security_policy: tp.Optional[
        tp.Union[type["TokenAuthenticationPolicy"], type["JWTCookieAuthenticationPolicy"]]
    ] = DEFAULT_SECURITY_POLICY,
) -> None:
    """
    Configure token-based authentication for a Pyramid application (with conflict detection).

    .. note::

        This function is intended to be used as a Pyramid configuration directive. By calling
        :meth:`pyramid.config.Configurator.action` with a unique ``discriminator``, it ensures
        that conflicts are detected if multiple parts of the application try to register the
        same directive.
    Example:
        1. **Add the directive** (typically in your ``includeme`` function):

        .. code-block:: python

           from pyramid.config import Configurator
           from myproject.auth import set_token_authentication

           def includeme(config: Configurator):
               # Register the custom directive
               config.add_directive(
                   'set_token_authentication',
                   set_token_authentication
               )

        2. **Use the directive** somewhere after including it:

        .. code-block:: python

           def main(global_config, **settings):
               config = Configurator(settings=settings)
               config.include('myproject')  # calls includeme(...)

               config.set_token_authentication(
                   long_term_token_model=MyTokenModel,
                   project_prefix='my_project',
                   login_callback=verify_user,
                   jwk_resolver=get_secret,
                   jwt_algorithm='HS256',
                   jwt_token_expiration_mins=120
               )

               return config.make_wsgi_app()

        **Accessing the Configured Values**

        Later in the application code, it can retrieve these values from ``request.registry``:

        .. code-block:: python

           @view_config(route_name='home')
           def home_view(request):
               long_term_token_model = request.registry.tet_auth_long_term_token_model
               prefix = request.registry.tet_auth_project_prefix
               # ... do something with these values ...

    Args:
        config: The current Pyramid :class:`pyramid.config.Configurator` instance.
        long_term_token_model: A token model class or object representing user tokens.
        project_prefix: A project-specific prefix (could be used for namespacing).
        user_id_column: Column name or attribute for user ID in the token model. Defaults to ``"user_id"``.
        login_callback: A callable to verify user credentials/status from the database.
        jwk_resolver: A callable that returns a secret key or keys for token signing.
        jwt_algorithm: The JWT algorithm to use (default: ``"HS256"``).
        jwt_token_expiration_mins: JWT expiration time in minutes (default: 15).
        access_token_header: The header name for the access token (default: ``"X-Access-Token"``).
        long_term_token_header: The header name for the long-term token (default: ``"X-Long-Token"``).
        default_claims: Default JWT registered claims to include in the token payload.
        security_policy: A custom security policy to use for token authentication.
    """

    def register():
        config.registry.tet_auth_long_term_token_model = long_term_token_model
        config.registry.tet_auth_project_prefix = project_prefix
        config.registry.tet_auth_user_id_column = user_id_column
        config.registry.tet_auth_access_token_header = access_token_header
        config.registry.tet_auth_long_term_token_header = long_term_token_header
        config.registry.tet_auth_access_token_cookie_name = access_token_cookie_name
        config.registry.tet_auth_long_term_token_cookie_name = long_term_token_cookie_name
        config.registry.tet_auth_default_claims = default_claims

        config.registry.tet_auth_login_callback = login_callback
        config.registry.tet_auth_jwk_resolver = jwk_resolver
        config.registry.tet_auth_jwt_algorithm = jwt_algorithm
        config.registry.tet_auth_jwt_expiration_mins = jwt_token_expiration_mins

    config.action(discriminator="set_token_authentication", callable=register)

    config.set_security_policy(security_policy)

    login_view_attr = (
        COOKIE_LOGIN_VIEW
        if isinstance(security_policy, JWTCookieAuthenticationPolicy)
        else DEFAULT_LOGIN_VIEW
    )
    config.add_view(
        AuthViews,
        attr=login_view_attr,
        route_name="tet_auth_login",
        renderer="json",
        request_method="POST",
        require_csrf=False,
        permission=NO_PERMISSION_REQUIRED,
    )

    config.add_view(
        AuthViews,
        attr="jwt_token",
        route_name="tet_auth_jwt",
        renderer="string",
        request_method="GET",
        require_csrf=False,
        permission=NO_PERMISSION_REQUIRED,
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
    id = Column(Integer, primary_key=True)
    secret_hash = Column(String, nullable=False)
    created_at = Column(DateTime(True), default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime(True), nullable=True)


class TetTokenService(RequestScopedBaseService):
    session: Session = autowired(Session)

    def __init__(self, request: Request):
        super().__init__(request=request)

        self.long_term_token_model: tp.Any = self.registry.tet_auth_long_term_token_model
        self.user_id_column: str = self.registry.tet_auth_user_id_column
        self.jwt_expiration_mins: int = self.registry.tet_auth_jwt_expiration_mins
        self.jwt_algorithm: str = self.registry.tet_auth_jwt_algorithm
        self.default_claims: JWTRegisteredClaims = self.registry.tet_auth_default_claims

    def create_long_term_token(
        self,
        user_id: tp.Any,
        project_prefix: str,
        expire_timestamp=None,
        description=None,
    ) -> str:
        """
        Generates a long-term token for a user with a project-specific prefix and stores it in the database.
        Args:
            user_id: The ID of the user for whom the token is generated.
            project_prefix: A prefix indicating the project this token is for.
            expire_timestamp: (Optional) Expiration timestamp for the token.
            description: (Optional) Description for the token.

        Returns:
            The plaintext long-term token with the project-specific prefix.
        """
        secret = secrets.token_bytes(32)
        hashed_secret = hashlib.sha256(secret).digest()

        stored_token = self.long_term_token_model(
            secret_hash=hashed_secret.hex(),
            created_at=datetime.now(UTC),
            expires_at=expire_timestamp,
        )
        setattr(stored_token, self.user_id_column, user_id)

        self.session.add(stored_token)
        self.session.flush()

        token_id = stored_token.id.to_bytes(8, "little")
        payload = token_id + secret
        token = f"{project_prefix}{payload.hex().upper()}"

        return token

    def retrieve_and_validate_token(self, token: str, prefix: str) -> tp.Any:
        """
        Retrieves and validates a long-term token from the database.

        Args:
            token: The token string to validate.
            prefix: The expected project-specific prefix for the token.

        Returns:
            The validated Token object from the database.

        Raises:
            ValueError: If the token is invalid, expired, or not found.
        """
        if not token.startswith(prefix):
            raise ValueError("Invalid token prefix")

        payload_hex = token[len(prefix) :]
        payload = bytes.fromhex(payload_hex)
        token_id_bytes = payload[:8]
        secret = payload[8:]

        token_id = int.from_bytes(token_id_bytes, "little")

        token_from_db = (
            self.session.query(self.long_term_token_model)
            .filter(self.long_term_token_model.id == token_id)
            .one_or_none()
        )

        if not token_from_db:
            raise ValueError("Token not found")

        if token_from_db.secret_hash != hashlib.sha256(secret).digest().hex():
            raise ValueError("Invalid token")

        if token_from_db.expires_at and token_from_db.expires_at < datetime.now(UTC):
            raise ValueError("Token expired")

        return token_from_db

    def create_short_term_jwt(self, user_id: tp.Any) -> str:
        """
        Generates a short-term JWT with a 15-minute expiration.

        Args:
            user_id: The ID of the user for whom the JWT is generated.
        Returns:
            The encoded JWT as a string.
        """
        # TODO: In the next update, we can add more encoding options here, such as headers, json_encoder.
        if not user_id:
            raise ValueError("User ID is required")

        payload = self.default_claims
        payload.user_id = user_id
        payload.iat = datetime.now(UTC)
        payload.exp = payload.iat + timedelta(minutes=self.jwt_expiration_mins)
        return jwt.encode(
            payload.to_dict(),
            self.registry.tet_auth_jwk_resolver(self.request),
            algorithm=self.jwt_algorithm,
        )

    def verify_jwt(self, token: str) -> tp.Optional[tp.Dict[str, tp.Any]]:
        """
        Verifies and decodes a JWT, ensuring it is valid and not expired.

        Args:
            token (str): The JWT to verify.

        Returns:
            - The ``decoded payload`` if the JWT is valid
            - ``None`` if the JWT is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                self.registry.tet_auth_jwk_resolver(self.request),
                algorithms=[self.jwt_algorithm],
                leeway=self.default_claims.leeway,
                audience=self.default_claims.aud,
                subject=self.default_claims.sub,
                issuer=self.default_claims.iss,
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None


class AuthViews:
    token_service: TetTokenService = autowired(TetTokenService)

    def __init__(self, request: Request):
        self.request = request
        self.registry = request.registry
        self.response = request.response
        self.long_term_token_header = self.registry.tet_auth_long_term_token_header
        self.access_token_header = self.registry.tet_auth_access_token_header
        self.project_prefix = self.registry.tet_auth_project_prefix
        self.access_token_cookie_name = self.registry.tet_auth_access_token_cookie_name
        self.long_term_token_cookie_name = self.registry.tet_auth_long_term_token_cookie_name

    def _set_cookie(
        self,
        name,
        value,
        max_age,
        domain=None,
        secure=True,
        httponly=True,
        samesite="Lax",
        overwrite=True,
        **kwargs,
    ):
        self.response.set_cookie(
            name=name,
            value=value,
            max_age=max_age,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            overwrite=overwrite,
            **kwargs,
        )

    def login(self) -> tp.Union[tp.Dict[str, tp.Any], HTTPForbidden, None]:
        login_callback = self.registry.tet_auth_login_callback
        user_id = login_callback(self.request)

        if user_id is None:
            raise HTTPUnauthorized()

        refresh_token = self.token_service.create_long_term_token(user_id, self.project_prefix)
        self.response.headers[self.long_term_token_header] = refresh_token

        access_token = self.token_service.create_short_term_jwt(user_id)
        self.response.headers[self.access_token_header] = access_token

        return {
            "success": True,
        }

    def cookie_login(self) -> tp.Union[tp.Dict[str, tp.Any], HTTPForbidden, None, Response]:
        response = self.login()
        self._set_cookie(
            name=self.access_token_cookie_name,
            value=self.response.headers[self.access_token_header],
            max_age=self.token_service.jwt_expiration_mins * 60,
        )
        self._set_cookie(
            name=self.long_term_token_cookie_name,
            value=self.response.headers[self.long_term_token_header],
            max_age=86400,
        )
        return response

    def jwt_token(self) -> str:
        token = self.request.headers.get(self.long_term_token_header)

        try:
            token_from_db = self.token_service.retrieve_and_validate_token(
                token, self.project_prefix
            )
        except ValueError as e:
            logger.exception(f"Error validating token: {e}")
            raise HTTPUnauthorized() from e

        user_id = getattr(token_from_db, self.token_service.user_id_column)

        jwt_token = self.token_service.create_short_term_jwt(user_id)

        self.response.headers[self.access_token_header] = jwt_token

        return "ok"


def includeme(config: Configurator):
    """Routes and stuff to register maybe under a prefix"""
    config.add_route("tet_auth_login", "login")
    config.add_route("tet_auth_jwt", "access-token")

    config.add_directive("set_token_authentication", set_token_authentication)

    config.include("pyramid_di")
    config.register_service_factory(
        lambda ctx, req: TetTokenService(request=req), TetTokenService, Interface
    )

    config.set_default_permission("view")
