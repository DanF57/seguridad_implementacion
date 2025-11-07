"""
Modelos de datos con lógica de negocio (Active Record Pattern)
Implementación basada en SQLAlchemy 2.0 (Declarative ORM)
"""

import bcrypt
import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session


class Base(DeclarativeBase):
    pass


# Enumeraciones
class UserStatus(str, Enum):
    PENDING_VALIDATION = "PENDING_VALIDATION"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    LOCKED = "LOCKED"


class TokenType(str, Enum):
    EMAIL_VALIDATION = "EMAIL_VALIDATION"
    PASSWORD_RECOVERY = "PASSWORD_RECOVERY"
    ACCOUNT_UNLOCK = "ACCOUNT_UNLOCK"


class LogEventType(str, Enum):
    USER_CREATED = "USER_CREATED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    ACCOUNT_ACTIVATED = "ACCOUNT_ACTIVATED"
    ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    MFA_VERIFIED = "MFA_VERIFIED"
    MFA_FAILED = "MFA_FAILED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(20), nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=UserStatus.PENDING_VALIDATION.value, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    two_factor_method: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    two_factor_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relaciones
    sessions: Mapped[list["Session"]] = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    tokens: Mapped[list["Token"]] = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.id:
            self.id = secrets.token_urlsafe(16)

    def login(self, password: str, db_session: Session) -> Optional["Session"]:
        """
        Intenta autenticar al usuario. Maneja intentos fallidos y bloqueo de cuenta.
        RS6: Bloquea después de 4 intentos fallidos.
        RS5: Termina sesión activa antes de crear una nueva.
        """
        # Verificar si la cuenta está bloqueada
        if self.is_locked():
            AuditLog.create_log(db_session, self.id, LogEventType.LOGIN_FAILURE.value, "Intento de login en cuenta bloqueada")
            return None

        # Verificar si la cuenta está activa
        if not self.is_active():
            AuditLog.create_log(db_session, self.id, LogEventType.LOGIN_FAILURE.value, "Intento de login en cuenta inactiva")
            return None

        # Verificar contraseña
        if not self.check_password(password):
            self._increment_failed_attempts()
            db_session.commit()
            AuditLog.create_log(db_session, self.id, LogEventType.LOGIN_FAILURE.value, f"Login fallido. Intentos: {self.failed_attempts}")
            return None

        # Contraseña correcta, resetear intentos fallidos
        self._reset_failed_attempts()
        
        # RS5: Terminar sesión activa antes de crear una nueva
        self.terminate_active_session(db_session)

        # Crear nueva sesión
        session = Session(
            user_id=self.id,
            session_token=secrets.token_urlsafe(32)
        )
        db_session.add(session)
        db_session.commit()
        
        AuditLog.create_log(db_session, self.id, LogEventType.LOGIN_SUCCESS.value, "Login exitoso")
        return session

    def verify_mfa(self, db_session: Session, code: str) -> bool:
        """
        Verifica el código MFA. Para esta práctica, acepta código estático "123456".
        """
        # Código estático para la práctica
        if code == "123456":
            active_session = self.get_active_session(db_session)
            if active_session:
                active_session.update_activity()
            db_session.commit()
            AuditLog.create_log(db_session, self.id, LogEventType.MFA_VERIFIED.value, "MFA verificado exitosamente")
            return True
        else:
            AuditLog.create_log(db_session, self.id, LogEventType.MFA_FAILED.value, "Código MFA incorrecto")
            return False

    def logout(self, db_session: Session) -> None:
        """Termina la sesión activa del usuario."""
        self.terminate_active_session(db_session)
        AuditLog.create_log(db_session, self.id, LogEventType.SESSION_TERMINATED.value, "Logout realizado")

    def get_active_session(self, db_session: Session) -> Optional["Session"]:
        """Obtiene la sesión activa del usuario si existe y es válida."""
        active_session = db_session.query(Session).filter(
            Session.user_id == self.id,
            Session.expires_at > datetime.utcnow()
        ).order_by(Session.created_at.desc()).first()
        
        if active_session and active_session.is_valid():
            return active_session
        return None

    def terminate_active_session(self, db_session: Session) -> None:
        """Termina todas las sesiones activas del usuario."""
        active_sessions = db_session.query(Session).filter(
            Session.user_id == self.id,
            Session.expires_at > datetime.utcnow()
        ).all()
        
        for session in active_sessions:
            session.terminate()
        
        db_session.commit()

    def check_password(self, password: str) -> bool:
        """Verifica si la contraseña proporcionada coincide con el hash almacenado."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def set_password(self, new_password: str) -> None:
        """Establece una nueva contraseña hasheada usando bcrypt."""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')

    def validate_account(self, token_value: str, db_session: Session) -> bool:
        """
        Valida la cuenta usando un token de validación de email.
        Cambia el estado a ACTIVE si el token es válido.
        """
        token = db_session.query(Token).filter(
            Token.user_id == self.id,
            Token.token_value == token_value,
            Token.type == TokenType.EMAIL_VALIDATION.value,
            Token.expires_at > datetime.utcnow()
        ).first()

        if token and token.is_valid():
            token.use_token()
            self.status = UserStatus.ACTIVE.value
            db_session.commit()
            AuditLog.create_log(db_session, self.id, LogEventType.ACCOUNT_ACTIVATED.value, "Cuenta validada exitosamente")
            return True
        
        return False

    def request_recovery_token(self, db_session: Session) -> "Token":
        """Genera un token de recuperación de contraseña."""
        # Invalidar tokens de recuperación previos
        old_tokens = db_session.query(Token).filter(
            Token.user_id == self.id,
            Token.type == TokenType.PASSWORD_RECOVERY.value
        ).all()
        for old_token in old_tokens:
            old_token.use_token()
        
        token = Token(
            user_id=self.id,
            token_value=secrets.token_urlsafe(32),
            type=TokenType.PASSWORD_RECOVERY.value,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db_session.add(token)
        db_session.commit()
        return token

    def validate_recovery_token(self, token_value: str, new_pass: str, db_session: Session) -> bool:
        """Valida un token de recuperación y cambia la contraseña."""
        token = db_session.query(Token).filter(
            Token.user_id == self.id,
            Token.token_value == token_value,
            Token.type == TokenType.PASSWORD_RECOVERY.value,
            Token.expires_at > datetime.utcnow()
        ).first()

        if token and token.is_valid():
            token.use_token()
            self.set_password(new_pass)
            self._reset_failed_attempts()
            db_session.commit()
            AuditLog.create_log(db_session, self.id, LogEventType.PASSWORD_CHANGED.value, "Contraseña recuperada exitosamente")
            return True
        
        return False

    def request_unlock_token(self, db_session: Session) -> "Token":
        """Genera un token para desbloquear la cuenta."""
        # Invalidar tokens de desbloqueo previos
        old_tokens = db_session.query(Token).filter(
            Token.user_id == self.id,
            Token.type == TokenType.ACCOUNT_UNLOCK.value
        ).all()
        for old_token in old_tokens:
            old_token.use_token()
        
        token = Token(
            user_id=self.id,
            token_value=secrets.token_urlsafe(32),
            type=TokenType.ACCOUNT_UNLOCK.value,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db_session.add(token)
        db_session.commit()
        return token

    def validate_unlock_token(self, token_value: str, db_session: Session) -> bool:
        """Valida un token de desbloqueo y desbloquea la cuenta."""
        token = db_session.query(Token).filter(
            Token.user_id == self.id,
            Token.token_value == token_value,
            Token.type == TokenType.ACCOUNT_UNLOCK.value,
            Token.expires_at > datetime.utcnow()
        ).first()

        if token and token.is_valid():
            token.use_token()
            self.status = UserStatus.ACTIVE.value
            self._reset_failed_attempts()
            db_session.commit()
            AuditLog.create_log(db_session, self.id, LogEventType.ACCOUNT_UNLOCKED.value, "Cuenta desbloqueada exitosamente")
            return True
        
        return False

    def deactivate(self) -> None:
        """Desactiva la cuenta del usuario."""
        self.status = UserStatus.INACTIVE.value

    def activate(self) -> None:
        """Activa la cuenta del usuario."""
        if self.status == UserStatus.LOCKED.value:
            # No se puede activar una cuenta bloqueada sin token
            return
        self.status = UserStatus.ACTIVE.value

    def is_locked(self) -> bool:
        """Verifica si la cuenta está bloqueada."""
        return self.status == UserStatus.LOCKED.value

    def is_active(self) -> bool:
        """Verifica si la cuenta está activa."""
        return self.status == UserStatus.ACTIVE.value

    def _increment_failed_attempts(self) -> None:
        """Incrementa el contador de intentos fallidos y bloquea si es necesario."""
        self.failed_attempts += 1
        if self.failed_attempts >= 4:
            self._lock_account()

    def _reset_failed_attempts(self) -> None:
        """Resetea el contador de intentos fallidos."""
        self.failed_attempts = 0

    def _lock_account(self) -> None:
        """Bloquea la cuenta del usuario."""
        self.status = UserStatus.LOCKED.value


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_active_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Relación
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.id:
            self.id = secrets.token_urlsafe(16)
        if not self.expires_at:
            # Sesión expira después de 24 horas
            self.expires_at = datetime.utcnow() + timedelta(hours=24)

    def terminate(self) -> None:
        """Termina la sesión estableciendo expires_at en el pasado."""
        self.expires_at = datetime.utcnow() - timedelta(seconds=1)

    def update_activity(self) -> None:
        """Actualiza la última actividad de la sesión."""
        self.last_active_at = datetime.utcnow()

    def is_expired(self) -> bool:
        """Verifica si la sesión ha expirado."""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Verifica si la sesión es válida (no expirada)."""
        return not self.is_expired()


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    token_value: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relación
    user: Mapped["User"] = relationship("User", back_populates="tokens")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.id:
            self.id = secrets.token_urlsafe(16)
        if 'used' not in kwargs:
            self.used = False

    def is_valid(self) -> bool:
        """Verifica si el token es válido (no expirado y no usado)."""
        return not self.used and datetime.utcnow() < self.expires_at

    def use_token(self) -> None:
        """Marca el token como usado."""
        self.used = True


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)

    # Relación
    user: Mapped["User"] = relationship("User", back_populates="audit_logs")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.id:
            self.id = secrets.token_urlsafe(16)

    @staticmethod
    def create_log(db_session: Session, user_id: str, event_type: str, details: str) -> "AuditLog":
        """Crea un nuevo registro de auditoría."""
        log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            details=details
        )
        db_session.add(log)
        db_session.commit()
        return log

