"""
Configuración de la base de datos SQLAlchemy
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

# Configuración de la base de datos SQLite
DATABASE_URL = "sqlite:///app.db"

# Crear el motor de la base de datos
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Necesario para SQLite con múltiples threads
    echo=False  # Cambiar a True para ver las queries SQL
)

# Crear el sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Inicializa la base de datos creando todas las tablas."""
    Base.metadata.create_all(bind=engine)

