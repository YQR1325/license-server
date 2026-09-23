# Rebuild forzado: 20260923035025
import hmac
import csv
import io
import os
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import SessionLocal, Base, engine
from app.models import Licencia, LogValidacion
from app.auth import (
    generar_clave_licencia, verificar_password,
    crear_sesion_admin, validar_sesion_admin,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PaydayPact License Server", version="3.0")

# Rutas ABSOLUTAS basadas en la ubicacion de este archivo
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Crear directorios si no existen
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SESSION_COOKIE = "pp_admin_session"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class VerificarRequest(BaseModel):
    machine_id: str = Field(..., min_length=36, max_length=36)
    license_key: str = Field(..., min_length=36, max_length=36)


@app.post("/api/verificar")
# rate limit removido para pruebas
def verificar_licencia(request: Request, req: VerificarRequest, db: Session = Depends(get_db)):
    machine_id = req.machine_id.strip().upper()
    license_key = req.license_key.strip().upper()
    ip = request.client.host if request.client else ""

    def log(resultado: str, motivo: str = ""):
        db.add(LogValidacion(machine_id=machine_id, resultado=resultado, motivo=motivo, ip=ip))
        db.commit()

    lic = db.query(Licencia).filter(Licencia.machine_id == machine_id).first()
    if not lic:
        log("error", "no_registrada")
        raise HTTPException(404, "Licencia no registrada")

    if not lic.activa:
        log("error", "revocada")
        raise HTTPException(403, "Licencia revocada")

    if not hmac.compare_digest(lic.license_key, license_key):
        log("error", "clave_invalida")
        raise HTTPException(401, "Clave invalida")

    if lic.fecha_expiracion and datetime.utcnow() > lic.fecha_expiracion:
        log("error", "expirada")
        raise HTTPException(403, "Licencia expirada")

    lic.ultimo_uso = datetime.utcnow()
    lic.usos = (lic.usos or 0) + 1
    log("ok")

    return {
        "valida": True,
        "cliente": lic.cliente,
        "expira": lic.fecha_expiracion.isoformat() if lic.fecha_expiracion else None,
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0"}


def requiere_admin(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if not validar_sesion_admin(token):
        raise HTTPException(401, "No autorizado")
    return True


@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse("/admin/login")


@app.get("/admin/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/admin/login", response_class=HTMLResponse)
def login_post(request: Request, password: str = Form(...)):
    if not verificar_password(password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Password incorrecta"},
            status_code=401,
        )
    token = crear_sesion_admin("admin")
    resp = RedirectResponse("/admin/panel", status_code=302)
    resp.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, samesite="strict", secure=True, max_age=3600 * 8,
    )
    return resp


@app.get("/admin/logout")
def logout():
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/admin/panel", response_class=HTMLResponse)
def panel(request: Request, q: str = "", estado: str = "", db: Session = Depends(get_db)):
    try:
        requiere_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")

    query = db.query(Licencia)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Licencia.machine_id.ilike(like)) |
            (Licencia.cliente.ilike(like)) |
            (Licencia.email.ilike(like))
        )
    if estado == "activa":
        query = query.filter(Licencia.activa == True)
    elif estado == "revocada":
        query = query.filter(Licencia.activa == False)
    elif estado == "expirada":
        query = query.filter(
            Licencia.fecha_expiracion != None,
            Licencia.fecha_expiracion < datetime.utcnow()
        )

    licencias = query.order_by(Licencia.id.desc()).all()

    total = db.query(func.count(Licencia.id)).scalar()
    activas = db.query(func.count(Licencia.id)).filter(Licencia.activa == True).scalar()
    revocadas = db.query(func.count(Licencia.id)).filter(Licencia.activa == False).scalar()

    return templates.TemplateResponse("panel.html", {
        "request": request,
        "licencias": licencias,
        "q": q,
        "estado": estado,
        "stats": {"total": total, "activas": activas, "revocadas": revocadas},
    })


@app.post("/admin/crear")
def admin_crear(
    request: Request,
    machine_id: str = Form(...),
    cliente: str = Form(""),
    email: str = Form(""),
    notas: str = Form(""),
    dias_validez: int = Form(365),
    db: Session = Depends(get_db),
):
    requiere_admin(request)
    machine_id = machine_id.strip().upper()
    if len(machine_id) != 36:
        return RedirectResponse("/admin/panel?err=guid_invalido", status_code=302)

    existente = db.query(Licencia).filter(Licencia.machine_id == machine_id).first()
    if existente:
        return RedirectResponse("/admin/panel?err=ya_existe", status_code=302)

    license_key = generar_clave_licencia(machine_id)
    expiracion = datetime.utcnow() + timedelta(days=dias_validez) if dias_validez > 0 else None

    db.add(Licencia(
        machine_id=machine_id,
        license_key=license_key,
        cliente=cliente,
        email=email,
        notas=notas,
        fecha_expiracion=expiracion,
    ))
    db.commit()
    return RedirectResponse("/admin/panel?ok=creada", status_code=302)


@app.post("/admin/revocar")
def admin_revocar(request: Request, machine_id: str = Form(...), db: Session = Depends(get_db)):
    requiere_admin(request)
    lic = db.query(Licencia).filter(Licencia.machine_id == machine_id.strip().upper()).first()
    if lic:
        lic.activa = False
        db.commit()
    return RedirectResponse("/admin/panel?ok=revocada", status_code=302)


@app.post("/admin/reactivar")
def admin_reactivar(request: Request, machine_id: str = Form(...), db: Session = Depends(get_db)):
    requiere_admin(request)
    lic = db.query(Licencia).filter(Licencia.machine_id == machine_id.strip().upper()).first()
    if lic:
        lic.activa = True
        db.commit()
    return RedirectResponse("/admin/panel?ok=reactivada", status_code=302)


@app.post("/admin/eliminar")
def admin_eliminar(request: Request, machine_id: str = Form(...), db: Session = Depends(get_db)):
    requiere_admin(request)
    lic = db.query(Licencia).filter(Licencia.machine_id == machine_id.strip().upper()).first()
    if lic:
        db.delete(lic)
        db.commit()
    return RedirectResponse("/admin/panel?ok=eliminada", status_code=302)


@app.get("/admin/exportar")
def admin_exportar(request: Request, db: Session = Depends(get_db)):
    requiere_admin(request)
    licencias = db.query(Licencia).order_by(Licencia.id.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["GUID", "Cliente", "Email", "Estado", "Expira", "Usos", "Ultimo uso", "Creada"])
    for l in licencias:
        writer.writerow([
            l.machine_id,
            l.cliente,
            l.email,
            "ACTIVA" if l.activa else "REVOCADA",
            l.fecha_expiracion.strftime("%Y-%m-%d") if l.fecha_expiracion else "Nunca",
            l.usos or 0,
            l.ultimo_uso.strftime("%Y-%m-%d %H:%M") if l.ultimo_uso else "",
            l.fecha_creacion.strftime("%Y-%m-%d") if l.fecha_creacion else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=licencias.csv"},
    )

