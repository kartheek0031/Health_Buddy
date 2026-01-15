import hashlib
import os
import secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.models import AuditEvent, CareTask, Clinic, ConsentGrant, Encounter, HealthRecord, Invitation, LoginSession, Patient, User, new_id, now_utc

load_dotenv()

app = FastAPI(title="Healthbuddy", docs_url="/api/docs", redoc_url=None)
password_hash = PasswordHash.recommended()
STATIC_DIR = Path(__file__).resolve().parent.parent / "public"
UPLOAD_DIR = Path(os.getenv("FILE_STORAGE_PATH", "data/uploads")).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
COOKIE_NAME = "hb_session"
SESSION_HOURS = 8
MAX_FILE_SIZE = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".txt"}


class BootstrapInput(BaseModel):
    clinic_name: str = Field(min_length=2, max_length=160)
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class InvitationInput(BaseModel):
    patient_name: str = Field(min_length=2, max_length=120)
    patient_email: str = Field(min_length=5, max_length=320)
    encounter_title: str = Field(min_length=2, max_length=180)
    visit_date: date


class ClaimInput(BaseModel):
    token: str = Field(min_length=32, max_length=160)
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    consent_to_clinic: bool


class AcceptInput(BaseModel):
    token: str = Field(min_length=32, max_length=160)
    consent_to_clinic: bool


class InvitationTokenInput(BaseModel):
    token: str = Field(min_length=32, max_length=160)


class RecordReviewInput(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    summary: str = Field(max_length=4000)


class TaskInput(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    due_date: date | None = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalized_email(value: str) -> str:
    return value.strip().casefold()


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def get_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_digest(token)))
    if not login or as_utc(login.expires_at) <= now_utc():
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")
    user = db.get(User, login.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return user


def require_staff(user: User = Depends(get_user)) -> User:
    if user.role != "clinic_staff" or not user.clinic_id:
        raise HTTPException(status_code=403, detail="Clinic staff access is required.")
    return user


def require_patient(user: User = Depends(get_user), db: Session = Depends(get_db)) -> Patient:
    if user.role != "patient":
        raise HTTPException(status_code=403, detail="Patient access is required.")
    patient = db.scalar(select(Patient).where(Patient.user_id == user.id))
    if not patient:
        raise HTTPException(status_code=403, detail="Patient profile is not available.")
    return patient


def set_session(response: Response, db: Session, user: User) -> None:
    token = secrets.token_urlsafe(40)
    db.add(LoginSession(user_id=user.id, token_hash=token_digest(token), expires_at=now_utc() + timedelta(hours=SESSION_HOURS)))
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_HOURS * 3600, httponly=True, secure=os.getenv("COOKIE_SECURE", "false").lower() == "true", samesite="strict", path="/")


def log_event(db: Session, user: User, action: str, resource_type: str, resource_id: str, patient_id: str | None = None) -> None:
    db.add(AuditEvent(actor_user_id=user.id, patient_id=patient_id, action=action, resource_type=resource_type, resource_id=resource_id))


def user_payload(user: User, db: Session) -> dict:
    clinic = db.get(Clinic, user.clinic_id) if user.clinic_id else None
    patient = db.scalar(select(Patient).where(Patient.user_id == user.id)) if user.role == "patient" else None
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role, "clinic_name": clinic.name if clinic else None, "patient_id": patient.id if patient else None}


def record_payload(record: HealthRecord) -> dict:
    return {"id": record.id, "title": record.title, "type": record.record_type, "date": record.record_date.isoformat(), "provider": record.provider_name, "summary": record.summary, "status": record.status, "file_name": record.file_name, "has_file": bool(record.file_key), "encounter_id": record.encounter_id, "created_at": record.created_at.isoformat()}


def grant_is_active(db: Session, patient_id: str, clinic_id: str, encounter_id: str) -> ConsentGrant | None:
    grants = db.scalars(select(ConsentGrant).where(ConsentGrant.patient_id == patient_id, ConsentGrant.clinic_id == clinic_id, ConsentGrant.encounter_id == encounter_id, ConsentGrant.revoked_at.is_(None))).all()
    return next((g for g in grants if as_utc(g.expires_at) > now_utc()), None)


def attach_invitation(db: Session, invitation: Invitation, user: User, patient: Patient) -> None:
    encounter = db.get(Encounter, invitation.encounter_id)
    if not encounter or encounter.patient_id:
        raise HTTPException(status_code=409, detail="This visit is already connected to an account.")
    encounter.patient_id = patient.id
    invitation.claimed_at = now_utc()
    records = db.scalars(select(HealthRecord).where(HealthRecord.encounter_id == encounter.id)).all()
    for record in records:
        record.patient_id = patient.id
    db.add(ConsentGrant(patient_id=patient.id, clinic_id=invitation.clinic_id, encounter_id=encounter.id, purpose="Post-consultation care", expires_at=now_utc() + timedelta(days=30)))
    log_event(db, user, "invitation_claimed_and_consent_granted", "encounter", encounter.id, patient.id)


def save_upload(upload: UploadFile) -> tuple[str, str, str, int]:
    filename = Path(upload.filename or "document").name
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Use a PDF, image, or plain text file.")
    content = upload.file.read(MAX_FILE_SIZE + 1)
    if not content:
        raise HTTPException(status_code=400, detail="The selected file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Choose a file smaller than 8 MB.")
    signatures = {".pdf": content.startswith(b"%PDF-"), ".png": content.startswith(b"\x89PNG\r\n\x1a\n"), ".jpg": content.startswith(b"\xff\xd8\xff"), ".jpeg": content.startswith(b"\xff\xd8\xff"), ".webp": len(content) > 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP", ".txt": True}
    if not signatures[extension]:
        raise HTTPException(status_code=415, detail="The file contents do not match the selected file type.")
    key = f"{new_id()}{extension}"
    (UPLOAD_DIR / key).write_bytes(content)
    content_type = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".txt": "text/plain"}[extension]
    return key, filename[:240], content_type, len(content)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/bootstrap")
def bootstrap(payload: BootstrapInput, response: Response, setup_key: str | None = Header(default=None, alias="X-Setup-Key"), db: Session = Depends(get_db)):
    configured = os.getenv("HEALTHBUDDY_SETUP_KEY", "")
    if len(configured) < 24:
        raise HTTPException(status_code=503, detail="Set a setup key of at least 24 characters before creating the first clinic account.")
    if not setup_key or not secrets.compare_digest(setup_key, configured):
        raise HTTPException(status_code=403, detail="The setup key is not valid.")
    if db.scalar(select(User.id).where(User.role == "clinic_staff")):
        raise HTTPException(status_code=409, detail="A clinic account has already been created.")
    user = User(email=normalized_email(payload.email), full_name=payload.full_name.strip(), password_hash=password_hash.hash(payload.password), role="clinic_staff")
    clinic = Clinic(name=payload.clinic_name.strip())
    db.add(clinic)
    db.flush()
    user.clinic_id = clinic.id
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    log_event(db, user, "clinic_bootstrapped", "clinic", clinic.id)
    set_session(response, db, user)
    db.commit()
    return {"user": user_payload(user, db)}


@app.post("/api/auth/login")
def login(payload: LoginInput, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == normalized_email(payload.email)))
    if not user or not password_hash.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    set_session(response, db, user)
    db.commit()
    return {"user": user_payload(user, db)}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        login_session = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_digest(token)))
        if login_session:
            db.delete(login_session)
            db.commit()
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=os.getenv("COOKIE_SECURE", "false").lower() == "true", samesite="strict")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: User = Depends(get_user), db: Session = Depends(get_db)):
    return {"user": user_payload(user, db)}


@app.post("/api/clinic/invitations")
def create_invitation(payload: InvitationInput, db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    email = normalized_email(payload.patient_email)
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    encounter = Encounter(clinic_id=staff.clinic_id, title=payload.encounter_title.strip(), visit_date=payload.visit_date, created_by=staff.id)
    db.add(encounter)
    db.flush()
    token = secrets.token_urlsafe(32)
    invitation = Invitation(clinic_id=staff.clinic_id, encounter_id=encounter.id, invited_email=email, patient_name=payload.patient_name.strip(), token_hash=token_digest(token), expires_at=now_utc() + timedelta(days=7), created_by=staff.id)
    db.add(invitation)
    db.flush()
    log_event(db, staff, "invitation_created", "invitation", invitation.id)
    db.commit()
    return {"id": invitation.id, "patient_name": invitation.patient_name, "patient_email": invitation.invited_email, "encounter_title": encounter.title, "visit_date": encounter.visit_date.isoformat(), "expires_at": invitation.expires_at.isoformat(), "claim_url": f"/join.html#token={token}"}


@app.get("/api/clinic/invitations")
def clinic_invitations(db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    rows = db.scalars(select(Invitation).where(Invitation.clinic_id == staff.clinic_id).order_by(Invitation.created_at.desc())).all()
    result = []
    for invitation in rows:
        encounter = db.get(Encounter, invitation.encounter_id)
        access_active = bool(encounter and encounter.patient_id and grant_is_active(db, encounter.patient_id, staff.clinic_id, encounter.id))
        all_records = db.scalars(select(HealthRecord).where(HealthRecord.encounter_id == invitation.encounter_id)).all()
        can_view_records = not (encounter and encounter.patient_id) or access_active
        visible_records = all_records if can_view_records else []
        result.append({"id": invitation.id, "patient_name": invitation.patient_name, "patient_email": invitation.invited_email, "encounter_title": encounter.title if encounter else "Visit", "visit_date": encounter.visit_date.isoformat() if encounter else "", "claimed": invitation.claimed_at is not None, "expired": as_utc(invitation.expires_at) <= now_utc(), "access_active": access_active, "record_count": len(visible_records), "records": [record_payload(r) for r in visible_records]})
    return {"invitations": result}


@app.post("/api/clinic/invitations/{invitation_id}/link")
def reissue_invitation_link(invitation_id: str, db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    invitation = db.get(Invitation, invitation_id)
    if not invitation or invitation.clinic_id != staff.clinic_id:
        raise HTTPException(status_code=404, detail="Invitation was not found.")
    if invitation.claimed_at:
        raise HTTPException(status_code=409, detail="This invitation has already been claimed.")
    token = secrets.token_urlsafe(32)
    invitation.token_hash = token_digest(token)
    invitation.expires_at = now_utc() + timedelta(days=7)
    db.commit()
    return {"claim_url": f"/join.html#token={token}", "expires_at": invitation.expires_at.isoformat()}


@app.post("/api/invitations/details")
def invitation_details(payload: InvitationTokenInput, db: Session = Depends(get_db)):
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == token_digest(payload.token)))
    if not invitation or invitation.claimed_at or as_utc(invitation.expires_at) <= now_utc():
        raise HTTPException(status_code=404, detail="This invitation is unavailable or has expired.")
    clinic = db.get(Clinic, invitation.clinic_id)
    encounter = db.get(Encounter, invitation.encounter_id)
    return {"clinic_name": clinic.name, "patient_name": invitation.patient_name, "email": invitation.invited_email, "visit_title": encounter.title, "visit_date": encounter.visit_date.isoformat(), "expires_at": invitation.expires_at.isoformat()}


@app.post("/api/invitations/claim")
def claim_invitation(payload: ClaimInput, response: Response, db: Session = Depends(get_db)):
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == token_digest(payload.token)))
    if not invitation or invitation.claimed_at or as_utc(invitation.expires_at) <= now_utc():
        raise HTTPException(status_code=404, detail="This invitation is unavailable or has expired.")
    if normalized_email(payload.email) != invitation.invited_email:
        raise HTTPException(status_code=403, detail="Use the email address this invitation was sent to.")
    if not payload.consent_to_clinic:
        raise HTTPException(status_code=422, detail="Confirm the clinic access details to continue.")
    user = User(email=invitation.invited_email, full_name=payload.full_name.strip(), password_hash=password_hash.hash(payload.password), role="patient")
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists. Sign in to that account, then open the invitation link again.")
    patient = Patient(user_id=user.id)
    db.add(patient)
    db.flush()
    attach_invitation(db, invitation, user, patient)
    set_session(response, db, user)
    db.commit()
    return {"user": user_payload(user, db)}


@app.post("/api/invitations/accept")
def accept_invitation(payload: AcceptInput, db: Session = Depends(get_db), user: User = Depends(get_user)):
    if user.role != "patient":
        raise HTTPException(status_code=403, detail="Sign in to a patient account to accept this invitation.")
    if not payload.consent_to_clinic:
        raise HTTPException(status_code=422, detail="Confirm the clinic access details to continue.")
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == token_digest(payload.token)))
    if not invitation or invitation.claimed_at or as_utc(invitation.expires_at) <= now_utc():
        raise HTTPException(status_code=404, detail="This invitation is unavailable or has expired.")
    if user.email != invitation.invited_email:
        raise HTTPException(status_code=403, detail="This invitation was sent to a different email address.")
    patient = db.scalar(select(Patient).where(Patient.user_id == user.id))
    if not patient:
        raise HTTPException(status_code=403, detail="Patient profile is not available.")
    attach_invitation(db, invitation, user, patient)
    db.commit()
    return {"ok": True}


@app.post("/api/clinic/invitations/{invitation_id}/records")
def clinic_add_record(invitation_id: str, title: str = Form(min_length=1, max_length=180), record_type: str = Form(min_length=1, max_length=48), record_date: date = Form(), provider_name: str = Form(default="", max_length=160), summary: str = Form(default="", max_length=4000), upload: UploadFile | None = File(default=None), db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    invitation = db.get(Invitation, invitation_id)
    if not invitation or invitation.clinic_id != staff.clinic_id:
        raise HTTPException(status_code=404, detail="Invitation was not found.")
    encounter = db.get(Encounter, invitation.encounter_id)
    if encounter.patient_id and not grant_is_active(db, encounter.patient_id, staff.clinic_id, encounter.id):
        raise HTTPException(status_code=403, detail="The patient has not granted current access for this visit.")
    file_key = file_name = content_type = None
    file_size = None
    if upload and upload.filename:
        file_key, file_name, content_type, file_size = save_upload(upload)
    record = HealthRecord(patient_id=encounter.patient_id, clinic_id=staff.clinic_id, encounter_id=encounter.id, title=title.strip(), record_type=record_type.strip(), record_date=record_date, provider_name=provider_name.strip() or (db.get(Clinic, staff.clinic_id).name), summary=summary.strip(), status="needs_review", source_user_id=staff.id, file_key=file_key, file_name=file_name, file_content_type=content_type, file_size=file_size)
    db.add(record)
    db.flush()
    log_event(db, staff, "record_added_by_clinic", "health_record", record.id, encounter.patient_id)
    db.commit()
    return {"record": record_payload(record)}


@app.get("/api/records")
def patient_records(db: Session = Depends(get_db), patient: Patient = Depends(require_patient)):
    records = db.scalars(select(HealthRecord).where(HealthRecord.patient_id == patient.id).order_by(HealthRecord.record_date.desc(), HealthRecord.created_at.desc())).all()
    return {"records": [record_payload(r) for r in records]}


@app.patch("/api/records/{record_id}")
def review_record(record_id: str, payload: RecordReviewInput, db: Session = Depends(get_db), patient: Patient = Depends(require_patient), user: User = Depends(get_user)):
    record = db.get(HealthRecord, record_id)
    if not record or record.patient_id != patient.id:
        raise HTTPException(status_code=404, detail="Record was not found.")
    record.title = payload.title.strip()
    record.summary = payload.summary.strip()
    record.status = "patient_confirmed"
    record.updated_at = now_utc()
    log_event(db, user, "record_reviewed", "health_record", record.id, patient.id)
    db.commit()
    return {"record": record_payload(record)}


@app.get("/api/records/{record_id}/file")
def get_record_file(record_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(get_user)):
    record = db.get(HealthRecord, record_id)
    if not record or not record.file_key:
        raise HTTPException(status_code=404, detail="File was not found.")
    allowed = False
    patient = db.scalar(select(Patient).where(Patient.user_id == user.id)) if user.role == "patient" else None
    if patient and record.patient_id == patient.id:
        allowed = True
    if user.role == "clinic_staff" and user.clinic_id and record.clinic_id == user.clinic_id and record.encounter_id:
        allowed = bool(record.patient_id and grant_is_active(db, record.patient_id, user.clinic_id, record.encounter_id))
    if not allowed:
        raise HTTPException(status_code=403, detail="You do not have access to this file.")
    file_path = UPLOAD_DIR / record.file_key
    if not file_path.is_file() or file_path.parent != UPLOAD_DIR:
        raise HTTPException(status_code=404, detail="File was not found.")
    log_event(db, user, "record_file_accessed", "health_record", record.id, record.patient_id)
    db.commit()
    return FileResponse(file_path, media_type=record.file_content_type or "application/octet-stream", filename=record.file_name or "health-record", headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"})


@app.get("/api/consents")
def patient_consents(db: Session = Depends(get_db), patient: Patient = Depends(require_patient)):
    grants = db.scalars(select(ConsentGrant).where(ConsentGrant.patient_id == patient.id).order_by(ConsentGrant.granted_at.desc())).all()
    result = []
    for grant in grants:
        clinic = db.get(Clinic, grant.clinic_id)
        encounter = db.get(Encounter, grant.encounter_id)
        result.append({"id": grant.id, "clinic_name": clinic.name if clinic else "Clinic", "encounter_title": encounter.title if encounter else "Visit", "purpose": grant.purpose, "granted_at": grant.granted_at.isoformat(), "expires_at": grant.expires_at.isoformat(), "revoked": grant.revoked_at is not None or as_utc(grant.expires_at) <= now_utc()})
    return {"consents": result}


@app.post("/api/consents/{grant_id}/revoke")
def revoke_consent(grant_id: str, db: Session = Depends(get_db), patient: Patient = Depends(require_patient), user: User = Depends(get_user)):
    grant = db.get(ConsentGrant, grant_id)
    if not grant or grant.patient_id != patient.id:
        raise HTTPException(status_code=404, detail="Access grant was not found.")
    if not grant.revoked_at:
        grant.revoked_at = now_utc()
        log_event(db, user, "clinic_access_revoked", "consent_grant", grant.id, patient.id)
        db.commit()
    return {"ok": True}


@app.get("/api/tasks")
def patient_tasks(db: Session = Depends(get_db), patient: Patient = Depends(require_patient)):
    tasks = db.scalars(select(CareTask).where(CareTask.patient_id == patient.id).order_by(CareTask.created_at.desc())).all()
    return {"tasks": [{"id": t.id, "title": t.title, "due_date": t.due_date.isoformat() if t.due_date else None, "status": t.status, "source_record_id": t.source_record_id} for t in tasks]}


@app.post("/api/tasks")
def create_task(payload: TaskInput, db: Session = Depends(get_db), patient: Patient = Depends(require_patient), user: User = Depends(get_user)):
    task = CareTask(patient_id=patient.id, title=payload.title.strip(), due_date=payload.due_date)
    db.add(task)
    db.flush()
    log_event(db, user, "patient_task_created", "care_task", task.id, patient.id)
    db.commit()
    return {"task": {"id": task.id, "title": task.title, "due_date": task.due_date.isoformat() if task.due_date else None, "status": task.status}}


@app.patch("/api/tasks/{task_id}")
def complete_task(task_id: str, status: str = Form(pattern="^(open|completed)$"), db: Session = Depends(get_db), patient: Patient = Depends(require_patient), user: User = Depends(get_user)):
    task = db.get(CareTask, task_id)
    if not task or task.patient_id != patient.id:
        raise HTTPException(status_code=404, detail="Follow-up was not found.")
    task.status = status
    log_event(db, user, "patient_task_status_changed", "care_task", task.id, patient.id)
    db.commit()
    return {"id": task.id, "status": task.status}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")
