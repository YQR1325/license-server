import os
import hmac
import hashlib
import bcrypt
from pathlib import Path
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer

# Intentar cargar .env (no falla si no existe)
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Leer variables de entorno
SECRET_KEY = os.environ.get("PAYDAYPACT_SECRET")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")

# Debug: mostrar todas las variables que empiezan con PAYDAY o ADMIN
if not SECRET_KEY:
    print("=== DEBUG: variables de entorno disponibles ===")
    for k, v in sorted(os.environ.items()):
        if "PAYDAY" in k.upper() or "ADMIN" in k.upper() or "SECRET" in k.upper():
            print(f"  {k} = {v[:20]}...")
    print("=== FIN DEBUG ===")
    raise RuntimeError(
        f"Falta PAYDAYPACT_SECRET. "
        f"Variables PAYDAY* disponibles: "
        f"{[k for k in os.environ if 'PAYDAY' in k.upper()]}"
    )

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="admin-session")


def generar_clave_licencia(machine_id: str) -> str:
    digest = hmac.new(
        SECRET_KEY.encode(),
        machine_id.upper().encode(),
        hashlib.sha256
    ).hexdigest().upper()
    h = digest[:32]
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def verificar_password(password: str) -> bool:
    if not ADMIN_PASSWORD_HASH:
        return False
    return bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH.encode())


def crear_sesion_admin(username: str) -> str:
    return serializer.dumps({"u": username})


def validar_sesion_admin(token: str, max_age: int = 3600 * 8) -> bool:
    try:
        serializer.loads(token, max_age=max_age)
        return True
    except Exception:
        return False
