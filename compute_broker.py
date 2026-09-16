"""
ApexSovereign.ai - Compute Broker Business Logic & Database Models
Defines SQLAlchemy schemas for Users, Leases, Transactions and lease dispatch endpoints.
"""

import os
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    DateTime,
    Text,
    Numeric,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Database Configuration & Session Factory
# ---------------------------------------------------------------------------
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./apexsovereign.db")

if RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL

engine_args: Dict[str, Any] = {"echo": False}
if DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}
else:
    engine_args["pool_size"] = 10
    engine_args["max_overflow"] = 20
    engine_args["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **engine_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ---------------------------------------------------------------------------
# SQLAlchemy Models
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    credits_balance = Column(Numeric(12, 4), default=1250.0000, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class ComputeLease(Base):
    __tablename__ = "compute_leases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=False)
    resource_tier = Column(String(32), nullable=False)
    cpu_cores = Column(Integer, nullable=False)
    memory_mb = Column(Integer, nullable=False)
    gpu_count = Column(Integer, default=0, nullable=False)
    cost_per_hour = Column(Numeric(10, 4), nullable=False)
    hold_amount = Column(Numeric(10, 4), nullable=False)
    status = Column(String(32), default="LEASED", nullable=False)
    lease_token = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), index=True, nullable=False)
    order_id = Column(String(128), unique=True, index=True, nullable=False)
    amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(8), default="USD", nullable=False)
    credits_added = Column(Numeric(12, 4), nullable=False)
    payment_status = Column(String(32), default="COMPLETED", nullable=False)
    payment_method = Column(String(32), default="PAYPAL", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_health() -> Dict[str, Any]:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"connected": True, "dialect": engine.dialect.name, "status": "HEALTHY"}
    except Exception as e:
        return {"connected": False, "error": str(e), "status": "UNAVAILABLE"}


# ---------------------------------------------------------------------------
# Hardware Tiers & Pricing Catalog
# ---------------------------------------------------------------------------
COMPUTE_TIER_CATALOG = {
    "STANDARD_CPU": {"name": "Standard Cloud CPU", "cpu": 4, "memory_mb": 16384, "gpu": 0, "cost_per_hour": 0.05},
    "HIGH_CPU": {"name": "High-Compute Parallel", "cpu": 16, "memory_mb": 65536, "gpu": 0, "cost_per_hour": 0.15},
    "GPU_T4": {"name": "NVIDIA T4 Tensor Core", "cpu": 8, "memory_mb": 32768, "gpu": 1, "cost_per_hour": 0.65},
    "GPU_A100": {"name": "NVIDIA A100 Tensor Core", "cpu": 12, "memory_mb": 81920, "gpu": 1, "cost_per_hour": 3.20},
    "GPU_H100": {"name": "NVIDIA H100 Hopper Extreme", "cpu": 16, "memory_mb": 122880, "gpu": 1, "cost_per_hour": 5.50},
}


def generate_hmac_lease_token(job_id: str, tenant_id: str, expires_epoch: int) -> str:
    """Generates a cryptographically secure HMAC-SHA256 lease authorization signature."""
    secret = os.getenv("APP_SECRET_API_KEY", "apexsovereign-dev-secret-key-default").encode("utf-8")
    message = f"{job_id}:{tenant_id}:{expires_epoch}".encode("utf-8")
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{job_id}:{tenant_id}:{expires_epoch}:{signature}"


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class LeaseRequest(BaseModel):
    tenant_id: str = Field(..., example="tenant-enterprise-4401")
    job_type: str = Field("LLM_INFERENCE_ORCHESTRATION")
    resource_tier: str = Field(..., example="GPU_A100")
    cpu_cores: Optional[int] = None
    memory_mb: Optional[int] = None
    gpu_count: Optional[int] = None
    duration_hours: float = Field(1.0, ge=0.25, le=72.0)
    idempotency_key: str = Field(...)


class LeaseResponse(BaseModel):
    job_id: str
    tenant_id: str
    resource_tier: str
    status: str
    estimated_cost: float
    remaining_balance: float
    lease_token: str
    expires_at: str


class ReleaseResponse(BaseModel):
    job_id: str
    status: str
    actual_cost: float
    refund_amount: float
    new_balance: float
    message: str


# ---------------------------------------------------------------------------
# Compute Router Endpoints
# ---------------------------------------------------------------------------
compute_router = APIRouter(prefix="/compute", tags=["Compute Broker"])


@compute_router.get("/tiers")
def list_tiers():
    return {"tiers": COMPUTE_TIER_CATALOG}


@compute_router.get("/tenant/{tenant_id}/balance")
def get_tenant_balance(tenant_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.tenant_id == tenant_id).first()
    if not user:
        user = User(tenant_id=tenant_id, email=f"{tenant_id}@apexsovereign.local", credits_balance=1250.0000)
        db.add(user)
        db.commit()
        db.refresh(user)

    return {
        "tenant_id": user.tenant_id,
        "email": user.email,
        "credits_balance": float(user.credits_balance),
    }


@compute_router.post("/dispatch", response_model=LeaseResponse)
def dispatch_compute_lease(req: LeaseRequest, db: Session = Depends(get_db)):
    """Allocates hardware cluster lease, holds balance, signs HMAC lease token."""
    tier_info = COMPUTE_TIER_CATALOG.get(req.resource_tier)
    if not tier_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Resource tier '{req.resource_tier}' is invalid.",
        )

    # Idempotency check
    existing_lease = db.query(ComputeLease).filter(ComputeLease.job_id == req.idempotency_key).first()
    if existing_lease:
        user = db.query(User).filter(User.tenant_id == req.tenant_id).first()
        return LeaseResponse(
            job_id=existing_lease.job_id,
            tenant_id=existing_lease.tenant_id,
            resource_tier=existing_lease.resource_tier,
            status=existing_lease.status,
            estimated_cost=float(existing_lease.hold_amount),
            remaining_balance=float(user.credits_balance) if user else 0.0,
            lease_token=existing_lease.lease_token,
            expires_at=existing_lease.expires_at.isoformat(),
        )

    user = db.query(User).filter(User.tenant_id == req.tenant_id).first()
    if not user:
        user = User(tenant_id=req.tenant_id, email=f"{req.tenant_id}@apexsovereign.local", credits_balance=1250.0000)
        db.add(user)
        db.commit()
        db.refresh(user)

    cost_per_hour = tier_info["cost_per_hour"]
    hold_amount = round(cost_per_hour * req.duration_hours, 4)

    if float(user.credits_balance) < hold_amount:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Insufficient balance. Required: ${hold_amount:.2f}, Available: ${float(user.credits_balance):.2f}.",
        )

    # Debit hold & create lease
    user.credits_balance = float(user.credits_balance) - hold_amount

    job_id = f"job-{uuid.uuid4().hex[:8]}"
    expires_epoch = int(time.time() + (req.duration_hours * 3600))
    expires_dt = datetime.fromtimestamp(expires_epoch, tz=timezone.utc)
    lease_token = generate_hmac_lease_token(job_id, req.tenant_id, expires_epoch)

    lease = ComputeLease(
        job_id=job_id,
        tenant_id=req.tenant_id,
        resource_tier=req.resource_tier,
        cpu_cores=req.cpu_cores or tier_info["cpu"],
        memory_mb=req.memory_mb or tier_info["memory_mb"],
        gpu_count=req.gpu_count if req.gpu_count is not None else tier_info["gpu"],
        cost_per_hour=cost_per_hour,
        hold_amount=hold_amount,
        status="LEASED",
        lease_token=lease_token,
        expires_at=expires_dt,
    )

    db.add(lease)
    db.commit()
    db.refresh(user)

    return LeaseResponse(
        job_id=job_id,
        tenant_id=req.tenant_id,
        resource_tier=req.resource_tier,
        status=lease.status,
        estimated_cost=hold_amount,
        remaining_balance=float(user.credits_balance),
        lease_token=lease_token,
        expires_at=expires_dt.isoformat(),
    )


@compute_router.get("/leases")
def list_leases(tenant_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ComputeLease)
    if tenant_id:
        query = query.filter(ComputeLease.tenant_id == tenant_id)
    leases = query.order_by(ComputeLease.created_at.desc()).limit(50).all()

    return {
        "count": len(leases),
        "leases": [
            {
                "job_id": l.job_id,
                "tenant_id": l.tenant_id,
                "tier": l.resource_tier,
                "status": l.status,
                "hold_cost": float(l.hold_amount),
                "lease_token": l.lease_token,
                "expires_at": l.expires_at.isoformat(),
                "created_at": l.created_at.isoformat(),
            }
            for l in leases
        ],
    }


@compute_router.post("/leases/{job_id}/release", response_model=ReleaseResponse)
def release_compute_lease(job_id: str, db: Session = Depends(get_db)):
    lease = db.query(ComputeLease).filter(ComputeLease.job_id == job_id).first()
    if not lease:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Lease '{job_id}' not found.")

    if lease.status in ["RELEASED", "TERMINATED"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Lease '{job_id}' is already {lease.status}.")

    user = db.query(User).filter(User.tenant_id == lease.tenant_id).first()

    created_ts = lease.created_at.replace(tzinfo=timezone.utc).timestamp()
    now_ts = datetime.now(timezone.utc).timestamp()
    duration_hours = max((now_ts - created_ts) / 3600.0, 0.05)

    actual_cost = round(min(duration_hours * float(lease.cost_per_hour), float(lease.hold_amount)), 4)
    refund_amount = round(float(lease.hold_amount) - actual_cost, 4)

    lease.status = "RELEASED"
    if user and refund_amount > 0:
        user.credits_balance = float(user.credits_balance) + refund_amount

    db.commit()

    return ReleaseResponse(
        job_id=lease.job_id,
        status="RELEASED",
        actual_cost=actual_cost,
        refund_amount=refund_amount,
        new_balance=float(user.credits_balance) if user else 0.0,
        message=f"Lease released. ${refund_amount:.4f} surplus refunded to balance.",
    )
