"""
Aplicación Streamlit para gestión de usuarios y autenticación
Implementa un sistema completo de registro, login, recuperación de contraseña y gestión de sesiones
"""

import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
from database import init_db, SessionLocal
from models import User, Session as UserSession, Token, AuditLog, UserStatus, TokenType


# Inicializar la base de datos al inicio
init_db()


def get_db() -> Session:
    """Obtiene una sesión de base de datos."""
    db = SessionLocal()
    try:
        return db
    finally:
        pass  # La sesión se cierra manualmente


def close_db(db: Session) -> None:
    """Cierra la sesión de base de datos."""
    db.close()


# Inicializar session_state si no existe
if "page" not in st.session_state:
    st.session_state.page = "login"
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "mfa_required" not in st.session_state:
    st.session_state.mfa_required = False


def render_registration():
    """Vista de Registro (RS1)"""
    st.title("Registro de Usuario")
    
    with st.form("registration_form"):
        first_name = st.text_input("Nombres")
        last_name = st.text_input("Apellidos")
        email = st.text_input("Email")
        phone = st.text_input("Teléfono")
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
        submit = st.form_submit_button("Registrarse")
        
        if submit:
            db = get_db()
            try:
                # Verificar si el usuario o email ya existen
                existing_user = db.query(User).filter(
                    (User.username == username) | (User.email == email)
                ).first()
                
                if existing_user:
                    st.error("El usuario o email ya existe")
                elif not all([first_name, last_name, email, phone, username, password]):
                    st.error("Por favor complete todos los campos")
                else:
                    # Crear nuevo usuario
                    user = User(
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        phone=phone,
                        username=username,
                        status=UserStatus.PENDING_VALIDATION.value
                    )
                    user.set_password(password)
                    db.add(user)
                    db.commit()
                    
                    # Crear token de validación
                    import secrets
                    from datetime import timedelta
                    token = Token(
                        user_id=user.id,
                        token_value=secrets.token_urlsafe(32),
                        type=TokenType.EMAIL_VALIDATION.value,
                        expires_at=datetime.utcnow() + timedelta(days=7)
                    )
                    db.add(token)
                    db.commit()
                    
                    # Crear log de auditoría
                    AuditLog.create_log(db, user.id, "USER_CREATED", "Usuario registrado exitosamente")
                    
                    st.success("Usuario registrado exitosamente")
                    st.info(f"**Token de validación (simulado):** {token.token_value}")
                    st.info("En un sistema real, este token se enviaría por email.")
                    st.session_state.registration_token = token.token_value
                    st.session_state.registration_user_id = user.id
                     # En render_registration(), después de st.info(...)
                    if st.button("Ir a Validar Cuenta"):
                        st.session_state.page = "validation"
                        st.rerun()
            except Exception as e:
                st.error(f"Error al registrar usuario: {str(e)}")
                db.rollback()
            finally:
                close_db(db)
    
    if st.button("Volver al Login"):
        st.session_state.page = "login"
        st.rerun()


def render_validation():
    """Vista de Validación de Cuenta (RS1)"""
    st.title("Validación de Cuenta")
    
    with st.form("validation_form"):
        token = st.text_input("Token de Validación")
        submit = st.form_submit_button("Validar Cuenta")
        
        if submit:
            db = get_db()
            try:
                # Buscar usuario por token
                token_obj = db.query(Token).filter(
                    Token.token_value == token,
                    Token.type == TokenType.EMAIL_VALIDATION.value
                ).first()
                
                if token_obj:
                    user = db.query(User).filter(User.id == token_obj.user_id).first()
                    if user and user.validate_account(token, db):
                        st.success("Cuenta validada exitosamente. Ahora puede iniciar sesión.")
                        st.session_state.page = "login"
                        st.rerun()
                    else:
                        st.error("Token inválido o expirado")
                else:
                    st.error("Token no encontrado")
            except Exception as e:
                st.error(f"Error al validar cuenta: {str(e)}")
            finally:
                close_db(db)
    
    if st.button("Volver al Login"):
        st.session_state.page = "login"
        st.rerun()


def render_login():
    """Vista de Login (RS2, RS5, RS6)"""
    st.title("Inicio de Sesión")
    
    # Si se requiere MFA
    if st.session_state.mfa_required:
        db = get_db()
        try:
            user = db.query(User).filter(User.id == st.session_state.user_id).first()
            if user:
                st.info("Se requiere verificación de dos factores (2FA)")
                mfa_code = st.text_input("Código 2FA", placeholder="Ingrese el código 2FA (123456 para esta práctica)")
                
                if st.button("Verificar"):
                    if user.verify_mfa(db, mfa_code):
                        st.success("MFA verificado exitosamente")
                        st.session_state.mfa_required = False
                        st.session_state.page = "dashboard"
                        st.rerun()
                    else:
                        st.error("Código 2FA incorrecto")
                
                if st.button("Cancelar"):
                    st.session_state.mfa_required = False
                    st.session_state.user_id = None
                    st.rerun()
        finally:
            close_db(db)
        return
    
    # Formulario de login normal
    with st.form("login_form"):
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
        submit = st.form_submit_button("Iniciar Sesión")
        
        if submit:
            db = get_db()
            try:
                user = db.query(User).filter(User.username == username).first()
                
                if not user:
                    st.error("Usuario o contraseña incorrectos")
                else:
                    session = user.login(password, db)
                    
                    if session:
                        st.session_state.user_id = user.id
                        st.session_state.mfa_required = True  # RS2: Requerir 2FA después del login
                        st.rerun()
                    else:
                        if user.is_locked():
                            st.error("Cuenta bloqueada. Use la opción de desbloqueo de cuenta.")
                        else:
                            st.error(f"Usuario o contraseña incorrectos. Intentos fallidos: {user.failed_attempts}/4")
            except Exception as e:
                st.error(f"Error al iniciar sesión: {str(e)}")
            finally:
                close_db(db)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Registrarse"):
            st.session_state.page = "register"
            st.rerun()
    with col2:
        if st.button("Recuperar Contraseña"):
            st.session_state.page = "recovery"
            st.rerun()

        # En render_login(), junto a "Registrarse"
    if st.button("Validar Cuenta"):
        st.session_state.page = "validation"
        st.rerun()
    
    if st.button("Desbloquear Cuenta"):
        st.session_state.page = "unlock"
        st.rerun()


def render_recovery():
    """Vista de Recuperación de Contraseña (RS4)"""
    st.title("Recuperación de Contraseña")
    
    if "recovery_token" not in st.session_state:
        st.session_state.recovery_token = None
    
    if st.session_state.recovery_token is None:
        # Paso 1: Solicitar token
        with st.form("recovery_request_form"):
            email = st.text_input("Email")
            submit = st.form_submit_button("Solicitar Token de Recuperación")
            
            if submit:
                db = get_db()
                try:
                    user = db.query(User).filter(User.email == email).first()
                    if user:
                        token = user.request_recovery_token(db)
                        st.success("Token de recuperación generado")
                        st.info(f"**Token de recuperación (simulado):** {token.token_value}")
                        st.info("En un sistema real, este token se enviaría por email.")
                        st.session_state.recovery_token = token.token_value
                        st.session_state.recovery_user_id = user.id
                    else:
                        st.error("Email no encontrado")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                finally:
                    close_db(db)
    else:
        # Paso 2: Validar token y cambiar contraseña
        with st.form("recovery_validate_form"):
            token = st.text_input("Token de Recuperación", value=st.session_state.recovery_token)
            new_password = st.text_input("Nueva Contraseña", type="password")
            confirm_password = st.text_input("Confirmar Contraseña", type="password")
            submit = st.form_submit_button("Cambiar Contraseña")
            
            if submit:
                if new_password != confirm_password:
                    st.error("Las contraseñas no coinciden")
                elif not new_password:
                    st.error("La contraseña no puede estar vacía")
                else:
                    db = get_db()
                    try:
                        user = db.query(User).filter(User.id == st.session_state.recovery_user_id).first()
                        if user and user.validate_recovery_token(token, new_password, db):
                            st.success("Contraseña cambiada exitosamente")
                            st.session_state.recovery_token = None
                            st.session_state.recovery_user_id = None
                            st.session_state.page = "login"
                            st.rerun()
                        else:
                            st.error("Token inválido o expirado")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
                    finally:
                        close_db(db)
    
    if st.button("Volver al Login"):
        st.session_state.recovery_token = None
        st.session_state.page = "login"
        st.rerun()


def render_unlock():
    """Vista de Desbloqueo de Cuenta (RS6)"""
    st.title("Desbloqueo de Cuenta")
    
    if "unlock_token" not in st.session_state:
        st.session_state.unlock_token = None
    
    if st.session_state.unlock_token is None:
        # Paso 1: Solicitar token
        with st.form("unlock_request_form"):
            email = st.text_input("Email")
            submit = st.form_submit_button("Solicitar Token de Desbloqueo")
            
            if submit:
                db = get_db()
                try:
                    user = db.query(User).filter(User.email == email).first()
                    if user:
                        if not user.is_locked():
                            st.warning("Esta cuenta no está bloqueada")
                        else:
                            token = user.request_unlock_token(db)
                            st.success("Token de desbloqueo generado")
                            st.info(f"**Token de desbloqueo (simulado):** {token.token_value}")
                            st.info("En un sistema real, este token se enviaría por email.")
                            st.session_state.unlock_token = token.token_value
                            st.session_state.unlock_user_id = user.id
                    else:
                        st.error("Email no encontrado")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                finally:
                    close_db(db)
    else:
        # Paso 2: Validar token y desbloquear
        with st.form("unlock_validate_form"):
            token = st.text_input("Token de Desbloqueo", value=st.session_state.unlock_token)
            submit = st.form_submit_button("Desbloquear Cuenta")
            
            if submit:
                db = get_db()
                try:
                    user = db.query(User).filter(User.id == st.session_state.unlock_user_id).first()
                    if user and user.validate_unlock_token(token, db):
                        st.success("Cuenta desbloqueada exitosamente")
                        st.session_state.unlock_token = None
                        st.session_state.unlock_user_id = None
                        st.session_state.page = "login"
                        st.rerun()
                    else:
                        st.error("Token inválido o expirado")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                finally:
                    close_db(db)
    
    if st.button("Volver al Login"):
        st.session_state.unlock_token = None
        st.session_state.page = "login"
        st.rerun()


def render_dashboard():
    """Vista de Dashboard (RS5, RS7)"""
    db = get_db()
    try:
        user = db.query(User).filter(User.id == st.session_state.user_id).first()
        
        if not user:
            st.error("Usuario no encontrado")
            st.session_state.user_id = None
            st.session_state.page = "login"
            st.rerun()
            return
        
        # RS7: Verificar sesión activa y expiración
        active_session = user.get_active_session(db)
        if not active_session or active_session.is_expired():
            st.warning("Su sesión ha expirado. Por favor, inicie sesión nuevamente.")
            user.logout(db)
            st.session_state.user_id = None
            st.session_state.page = "login"
            st.rerun()
            return
        
        # Actualizar actividad de la sesión
        active_session.update_activity()
        db.commit()
        
        st.title(f"Bienvenido, {user.username}")
        st.info(f"Estado de la cuenta: {user.status}")
        
        # Botón de Logout
        if st.button("Cerrar Sesión"):
            user.logout(db)
            st.session_state.user_id = None
            st.session_state.page = "login"
            st.rerun()
        
        # RS5: Panel de administración (solo para usuario "admin")
        if user.username == "admin":
            st.divider()
            st.subheader("Panel de Administración")
            
            # Lista de todos los usuarios
            all_users = db.query(User).all()
            
            if all_users:
                st.write("**Gestión de Usuarios:**")
                for u in all_users:
                    col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
                    with col1:
                        st.write(f"**{u.username}** ({u.email})")
                    with col2:
                        st.write(f"Estado: {u.status}")
                    with col3:
                        if u.status != UserStatus.ACTIVE.value and u.id != user.id:
                            if st.button("Activar", key=f"activate_{u.id}"):
                                u.activate()
                                db.commit()
                                AuditLog.create_log(db, u.id, "ACCOUNT_ACTIVATED", f"Activado por admin {user.username}")
                                st.rerun()
                    with col4:
                        if u.status == UserStatus.ACTIVE.value and u.id != user.id:
                            if st.button("Desactivar", key=f"deactivate_{u.id}"):
                                u.deactivate()
                                db.commit()
                                AuditLog.create_log(db, u.id, "ACCOUNT_DEACTIVATED", f"Desactivado por admin {user.username}")
                                st.rerun()
                    st.divider()
            
            # Ver logs de auditoría
            st.subheader("Logs de Auditoría")
            logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
            if logs:
                for log in logs:
                    log_user = db.query(User).filter(User.id == log.user_id).first()
                    username = log_user.username if log_user else "N/A"
                    st.write(f"**{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** - {username} - {log.event_type}: {log.details}")
            else:
                st.info("No hay logs de auditoría")
    finally:
        close_db(db)


# Router principal
def main():
    """Función principal que enruta a las diferentes vistas."""
    if st.session_state.user_id and not st.session_state.mfa_required and st.session_state.page != "dashboard":
        # Si hay un usuario logueado, ir al dashboard
        st.session_state.page = "dashboard"
    
    if st.session_state.page == "register":
        render_registration()
    elif st.session_state.page == "validation":
        render_validation()
    elif st.session_state.page == "login":
        render_login()
    elif st.session_state.page == "recovery":
        render_recovery()
    elif st.session_state.page == "unlock":
        render_unlock()
    elif st.session_state.page == "dashboard":
        render_dashboard()
    else:
        st.session_state.page = "login"
        st.rerun()


if __name__ == "__main__":
    main()

