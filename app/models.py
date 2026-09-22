from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from datetime import datetime
from app.database import Base


class Licencia(Base):
    __tablename__ = "licencias"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(String, unique=True, index=True, nullable=False)
    license_key = Column(String, unique=True, index=True, nullable=False)
    cliente = Column(String, default="")
    email = Column(String, default="")
    notas = Column(Text, default="")
    activa = Column(Boolean, default=True)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    fecha_expiracion = Column(DateTime, nullable=True)
    ultimo_uso = Column(DateTime, nullable=True)
    usos = Column(Integer, default=0)


class LogValidacion(Base):
    __tablename__ = "logs_validacion"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(String, index=True)
    fecha = Column(DateTime, default=datetime.utcnow)
    resultado = Column(String)
    motivo = Column(Text, default="")
    ip = Column(String, default="")
