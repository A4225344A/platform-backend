import asyncio
import hmac
import os
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
from psycopg.types.json import Jsonb

from .db import REQUIRED_TABLES, create_pool
from .errors import AppError
from .models import (
    ApprovalCreate,
    ApprovalDecision,
    ApprovalList,
    ApprovalRead,
    AuditLogList,
    Counters,
    IncidentDetail,
    NeedYou,
    Overview,
    ScorecardLatest,
    SecretRotationAuditCreate,
    AuditLogRead,
)
from .validation import validate_action

SCORECARD_LAST_EVAL = Gauge(
    "engops_scorecard_last_eval_timestamp_seconds",
    "Unix timestamp of the last successful scorecard evaluation.",
)


async def expire_stale_approvals(pool: Any) -> None:
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            "UPDATE approvals SET status='expired' "
            "WHERE status='pending' AND expires_at < now() "
            "RETURNING id"
        )
        for row in await cursor.fetchall():
            await connection.execute(
                "INSERT INTO audit_log (actor, verb, object, after) "
                "VALUES (%s, %s, %s, %s)",
                ("system", "approval.expire", str(row["id"]), Jsonb({"status": "expired"})),
            )


async def expiry_loop(pool: Any) -> None:
    while True:
        with suppress(Exception):
            await expire_stale_approvals(pool)
        await asyncio.sleep(120)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with create_pool() as pool:
        app.state.db_pool = pool
        task = asyncio.create_task(expiry_loop(pool))
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="EngOps API", version="0.1.0", lifespan=lifespan)


ORIGIN_VERIFY_HEADER = "x-engops-origin-verify"


def bearer_token_matches(authorization: str | None, expected: str | None) -> bool:
    if not expected:
        return False
    scheme, _, supplied = (authorization or "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(supplied, expected)


def api_boundary_authorized(origin_header: str | None, authorization: str | None) -> bool:
    expected_origin = os.environ.get("ENGOPS_API_ORIGIN_VERIFY_TOKEN")
    if not expected_origin:
        return True
    if origin_header and hmac.compare_digest(origin_header, expected_origin):
        return True
    return bearer_token_matches(authorization, os.environ.get("ENGOPS_API_TOKEN"))


@app.middleware("http")
async def enforce_api_origin_boundary(request: Request, call_next: Any) -> Response:
    is_api_request = request.url.path == "/api" or request.url.path.startswith("/api/")
    is_authorized = api_boundary_authorized(
        request.headers.get(ORIGIN_VERIFY_HEADER),
        request.headers.get("authorization"),
    )
    if is_api_request and not is_authorized:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "forbidden"})
    return await call_next(request)


def pool_from_request(request: Request) -> Any:
    return request.app.state.db_pool


def require_machine_token(authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("ENGOPS_API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="ENGOPS_API_TOKEN 尚未設定")
    if not bearer_token_matches(authorization, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授權")


def require_decision_token(authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("ENGOPS_DECISION_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="ENGOPS_DECISION_TOKEN not configured")
    if not bearer_token_matches(authorization, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.get("/readyz")
async def readyz(request: Request) -> dict[str, Any]:
    pool = pool_from_request(request)
    names = [f"public.{name}" for name in REQUIRED_TABLES]
    try:
        async with pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT name, to_regclass(name) AS oid "
                "FROM unnest(%s::text[]) AS required(name)",
                (names,),
            )
            rows = await cursor.fetchall()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="資料庫尚未可用") from exc
    missing = [row["name"] for row in rows if row["oid"] is None]
    if missing:
        raise HTTPException(status_code=503, detail=f"必要資料表尚未就緒: {', '.join(missing)}")
    return {"ok": True, "required_tables": list(REQUIRED_TABLES)}


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    pool = pool_from_request(request)
    try:
        async with pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT extract(epoch FROM max(evaluated_at)) AS last_eval "
                "FROM scorecard_results"
            )
            row = await cursor.fetchone()
        SCORECARD_LAST_EVAL.set(float(row["last_eval"]) if row and row["last_eval"] else 0)
    except Exception:
        SCORECARD_LAST_EVAL.set(0)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


async def prometheus_l0_estimate(pool: Any) -> int:
    prom_url = os.environ.get("PROM_URL")
    if not prom_url:
        return 0
    async with pool.connection() as connection:
        cursor = await connection.execute("SELECT service FROM service_catalog ORDER BY service")
        services = [row["service"] for row in await cursor.fetchall()]
        cursor = await connection.execute(
            "SELECT count(*) AS n FROM incidents i JOIN service_catalog c ON c.service=i.service "
            "WHERE i.created_at >= now() - interval '24 hours'"
        )
        catalog_alerts = (await cursor.fetchone())["n"]
    if not services:
        return 0
    # PromQL labels are escaped before interpolation; service names come from the catalog.
    regex = "|".join(service.replace("\\", "\\\\").replace(".", "\\.") for service in services)
    query = (
        'sum(increase(kube_pod_container_status_restarts_total{namespace="default",'
        f'pod=~"({regex})-.*"}}[24h]))'
    )
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{prom_url.rstrip('/')}/api/v1/query", params={"query": query})
            response.raise_for_status()
            results = response.json().get("data", {}).get("result", [])
            restarts = float(results[0]["value"][1]) if results else 0
            return max(0, round(restarts) - int(catalog_alerts))
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
        return 0


async def overview_data(pool: Any) -> dict[str, Any]:
    async with pool.connection() as connection:
        cursor = await connection.execute(
            """WITH recent_incidents AS (
                 SELECT id, status FROM incidents WHERE created_at >= now() - interval '24 hours'
               ), diagnosed AS (
                 SELECT count(DISTINCT s.incident_id) AS n FROM incident_steps s
                 JOIN recent_incidents i ON i.id=s.incident_id WHERE s.step='judged'
               ), rem AS (
                 SELECT count(*) FILTER (WHERE action IN ('restart','scale')) AS auto_remediated,
                   count(*) FILTER (WHERE action='notify_only') AS notify_only,
                   count(*) FILTER (WHERE action IN ('restart','scale') AND verified IS TRUE) AS verified,
                   count(*) FILTER (WHERE action IN ('restart','scale') AND verified IS FALSE) AS verify_failed
                 FROM remediation_log WHERE created_at >= now() - interval '24 hours'
               )
               SELECT (SELECT count(*) FROM recent_incidents) AS alerts,
                 (SELECT n FROM diagnosed) AS ai_diagnosed, rem.auto_remediated, rem.notify_only,
                 rem.verified, rem.verify_failed,
                 (SELECT count(*) FROM recent_incidents WHERE status='skipped_cooldown') AS skipped_cooldown
               FROM rem"""
        )
        counters_row = await cursor.fetchone()
        cursor = await connection.execute(
            """SELECT id, kind, service, action,
                 greatest(0, extract(epoch FROM (now()-requested_at)))::int AS waiting_seconds,
                 CASE WHEN kind='policy_change' THEN '/approvals'
                      ELSE '/incidents/' || incident_id END AS href
               FROM approvals WHERE status='pending' AND expires_at >= now()
               ORDER BY requested_at"""
        )
        approval_needs = await cursor.fetchall()
        cursor = await connection.execute(
            """SELECT i.id, i.service, i.status, i.alertname,
                 greatest(0, extract(epoch FROM (now()-COALESCE(i.started_at,i.created_at))))::int AS waiting_seconds
               FROM incidents i
               WHERE i.status='running' AND now()-COALESCE(i.started_at,i.created_at) > interval '5 minutes'
               ORDER BY i.created_at DESC"""
        )
        stale_incidents = await cursor.fetchall()
        cursor = await connection.execute(
            """SELECT DISTINCT i.service FROM incidents i
               LEFT JOIN service_catalog c ON c.service=i.service
               WHERE c.service IS NULL AND i.created_at >= now() - interval '24 hours'"""
        )
        catalog_gaps = await cursor.fetchall()
        cursor = await connection.execute(
            """SELECT id, service, alertname, status, COALESCE(started_at,created_at) AS started_at
               FROM incidents ORDER BY created_at DESC LIMIT 10"""
        )
        recent = await cursor.fetchall()

    needs = [NeedYou(**row) for row in approval_needs]
    needs.extend(
        NeedYou(id=row["id"], kind="timeline_stale", service=row["service"], action=None,
                waiting_seconds=row["waiting_seconds"], href=f"/incidents/{row['id']}")
        for row in stale_incidents
    )
    needs.extend(
        NeedYou(id=None, kind="catalog_gap", service=row["service"], action=None,
                waiting_seconds=None, href=None)
        for row in catalog_gaps
    )
    counters = Counters(l0_absorbed=await prometheus_l0_estimate(pool), **counters_row)
    return {
        "counters_computed_at": datetime.now(timezone.utc),
        "counters": counters,
        "needs_you": needs,
        "recent": [dict(row) for row in recent],
    }


@app.get("/api/v1/overview", response_model=Overview)
async def overview(pool: Any = Depends(pool_from_request)) -> Overview:
    return Overview(**await overview_data(pool))


async def latest_scorecard_data(scorecard_id: str, pool: Any) -> dict[str, Any]:
    async with pool.connection() as connection:
        cursor = await connection.execute("SELECT id, name FROM scorecards WHERE id=%s", (scorecard_id,))
        scorecard = await cursor.fetchone()
        if scorecard is None:
            raise HTTPException(status_code=404, detail="scorecard not found")

        cursor = await connection.execute(
            """SELECT service, evaluated_at, checks, passed, total
               FROM scorecard_results
               WHERE scorecard_id=%s
                 AND evaluated_at=(SELECT max(evaluated_at) FROM scorecard_results WHERE scorecard_id=%s)
               ORDER BY service""",
            (scorecard_id, scorecard_id),
        )
        rows = await cursor.fetchall()

    services = [
        {
            "service": row["service"],
            "checks": row["checks"],
            "passed": row["passed"],
            "total": row["total"],
        }
        for row in rows
    ]
    passed = sum(row["passed"] for row in rows)
    total = sum(row["total"] for row in rows)
    return {
        "scorecard_id": scorecard["id"],
        "name": scorecard["name"],
        "evaluated_at": rows[0]["evaluated_at"] if rows else None,
        "services": services,
        "totals": {
            "passed": passed,
            "total": total,
            "percent": round((passed / total) * 100) if total else None,
        },
    }


@app.get("/api/v1/scorecards/{scorecard_id}/latest", response_model=ScorecardLatest)
async def latest_scorecard(scorecard_id: str, pool: Any = Depends(pool_from_request)) -> ScorecardLatest:
    return ScorecardLatest(**await latest_scorecard_data(scorecard_id, pool))


async def approval_list_data(approval_status: str, pool: Any, limit: int = 50) -> dict[str, Any]:
    allowed_statuses = {"pending", "approved", "rejected", "expired", "all"}
    if approval_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="unsupported approval status")

    async with pool.connection() as connection:
        cursor = await connection.execute(
            """SELECT id, kind, service, action, payload, incident_id, trace_id, status,
                    pr_number, pr_url, base_commit_sha, requested_by, requested_at, expires_at,
                    decided_by, decided_at, decision_note,
                    greatest(0, extract(epoch FROM (now()-requested_at)))::int AS waiting_seconds
               FROM approvals
               WHERE (%s='all' OR status=%s)
                 AND (%s!='pending' OR expires_at >= now())
               ORDER BY requested_at DESC
               LIMIT %s""",
            (approval_status, approval_status, approval_status, limit),
        )
        rows = await cursor.fetchall()
    return {"status": approval_status, "approvals": [dict(row) for row in rows]}


@app.get("/api/v1/approvals", response_model=ApprovalList)
async def list_approvals(
    approval_status: Literal["pending", "approved", "rejected", "expired", "all"] = Query("pending", alias="status"),
    limit: int = Query(50, ge=1, le=100),
    pool: Any = Depends(pool_from_request),
) -> ApprovalList:
    return ApprovalList(**await approval_list_data(approval_status, pool, limit))


def approval_audit_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    snapshot = dict(row)
    for key, value in list(snapshot.items()):
        if isinstance(value, datetime):
            snapshot[key] = value.isoformat()
    return snapshot


async def decide_approval_data(approval_id: int, decision: ApprovalDecision, pool: Any) -> dict[str, Any]:
    verb = "approval.approve" if decision.decision == "approved" else "approval.reject"
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            """SELECT id, kind, service, action, payload, incident_id, trace_id, status,
                    pr_number, pr_url, base_commit_sha, requested_by, requested_at, expires_at,
                    decided_by, decided_at, decision_note,
                    greatest(0, extract(epoch FROM (now()-requested_at)))::int AS waiting_seconds
               FROM approvals WHERE id=%s
               FOR UPDATE""",
            (approval_id,),
        )
        before = await cursor.fetchone()
        if before is None:
            raise HTTPException(status_code=404, detail="approval not found")
        if before["status"] != "pending":
            raise HTTPException(status_code=409, detail="approval is already decided")
        if before["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=409, detail="approval is expired")

        cursor = await connection.execute(
            """UPDATE approvals
               SET status=%s,
                   decided_by=%s,
                   decided_at=now(),
                   decision_note=%s,
                   base_commit_sha=COALESCE(%s, base_commit_sha)
               WHERE id=%s
               RETURNING id, kind, service, action, payload, incident_id, trace_id, status,
                         pr_number, pr_url, base_commit_sha, requested_by, requested_at, expires_at,
                         decided_by, decided_at, decision_note,
                         greatest(0, extract(epoch FROM (now()-requested_at)))::int AS waiting_seconds""",
            (
                decision.decision,
                decision.decided_by,
                decision.decision_note,
                decision.base_commit_sha,
                approval_id,
            ),
        )
        after = await cursor.fetchone()
        await connection.execute(
            "INSERT INTO audit_log (actor, verb, object, before, after, trace_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (
                decision.decided_by,
                verb,
                str(approval_id),
                Jsonb(approval_audit_snapshot(before)),
                Jsonb(approval_audit_snapshot(after)),
                after["trace_id"],
            ),
        )
    return dict(after)


@app.post(
    "/api/v1/approvals/{approval_id}/decision",
    response_model=ApprovalRead,
    dependencies=[Depends(require_decision_token)],
)
async def decide_approval(
    approval_id: int,
    decision: ApprovalDecision,
    pool: Any = Depends(pool_from_request),
) -> ApprovalRead:
    return ApprovalRead(**await decide_approval_data(approval_id, decision, pool))


async def record_secret_rotation_audit_data(payload: SecretRotationAuditCreate, pool: Any) -> dict[str, Any]:
    object_name = f"{payload.secret_ref}/{payload.key}"
    after = {
        "sha256": payload.sha256,
        "secret_ref": payload.secret_ref,
        "key": payload.key,
        "storage": payload.storage,
        "purpose": payload.purpose,
    }
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            """INSERT INTO audit_log (actor, verb, object, after)
               VALUES (%s, %s, %s, %s)
               RETURNING id, at, actor, verb, object, after""",
            (payload.actor, "secret.rotate", object_name, Jsonb(after)),
        )
        row = await cursor.fetchone()
    return dict(row)


@app.post(
    "/api/v1/audit-log/secret-rotation",
    response_model=AuditLogRead,
    dependencies=[Depends(require_decision_token)],
    status_code=201,
)
async def record_secret_rotation_audit(
    payload: SecretRotationAuditCreate,
    pool: Any = Depends(pool_from_request),
) -> AuditLogRead:
    return AuditLogRead(**await record_secret_rotation_audit_data(payload, pool))


async def audit_log_list_data(pool: Any, limit: int = 50, verb: str | None = None) -> dict[str, Any]:
    async with pool.connection() as connection:
        cursor = await connection.execute(
            """SELECT id, at, actor, verb, object, before, after, trace_id
               FROM audit_log
               WHERE (%s::text IS NULL OR verb=%s)
               ORDER BY at DESC
               LIMIT %s""",
            (verb, verb, limit),
        )
        rows = await cursor.fetchall()
    return {"audit_log": [dict(row) for row in rows]}


@app.get("/api/v1/audit-log", response_model=AuditLogList)
async def list_audit_log(
    limit: int = Query(50, ge=1, le=100),
    verb: str | None = Query(default=None, min_length=1, max_length=120),
    pool: Any = Depends(pool_from_request),
) -> AuditLogList:
    return AuditLogList(**await audit_log_list_data(pool, limit, verb))


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentDetail)
async def incident_detail(incident_id: int, pool: Any = Depends(pool_from_request)) -> IncidentDetail:
    async with pool.connection() as connection:
        cursor = await connection.execute(
            """SELECT i.id, i.service, COALESCE(i.started_at,i.created_at) AS started_at,
                 COALESCE((SELECT max(at) FROM incident_steps WHERE incident_id=i.id),
                          i.started_at, i.created_at) AS latest_at,
                 i.status, c.log_query_url_template
               FROM incidents i LEFT JOIN service_catalog c ON c.service=i.service WHERE i.id=%s""",
            (incident_id,),
        )
        incident = await cursor.fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="事故不存在")
        cursor = await connection.execute(
            "SELECT at, step, detail FROM incident_steps WHERE incident_id=%s ORDER BY at",
            (incident_id,),
        )
        timeline = await cursor.fetchall()
    template = incident["log_query_url_template"]
    return IncidentDetail(
        id=incident["id"], service=incident["service"], started_at=incident["started_at"],
        timeline=timeline,
        timeline_stale=incident["status"] == "running" and (time.time() - incident["latest_at"].timestamp() > 300),
        agent_log_url=template.replace("%s", incident["service"]) if template else None,
    )


@app.post("/api/v1/approvals", status_code=201)
async def create_approval(payload: ApprovalCreate, pool: Any = Depends(pool_from_request)) -> dict[str, Any]:
    try:
        validate_action(payload.kind, payload.action, payload.payload.model_dump())
        async with pool.connection() as connection, connection.transaction():
            cursor = await connection.execute(
                """INSERT INTO approvals (kind, action, payload, requested_by)
                   VALUES (%s,%s,%s,%s) RETURNING id, kind, action, payload, status, requested_at, expires_at""",
                (payload.kind, payload.action, Jsonb(payload.payload.model_dump()), "lab-ui"),
            )
            row = await cursor.fetchone()
            await connection.execute(
                "INSERT INTO audit_log (actor,verb,object,after) VALUES (%s,%s,%s,%s)",
                (
                    "lab-ui",
                    "approval.create",
                    str(row["id"]),
                    Jsonb({"kind": row["kind"], "action": row["action"], "status": row["status"]}),
                ),
            )
    except AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        if "approvals_dedup" in str(exc):
            raise HTTPException(status_code=409, detail="同類型提議已有待處理項目") from exc
        raise
    return dict(row)


@app.post("/api/v1/scorecards/{scorecard_id}/evaluate", dependencies=[Depends(require_machine_token)])
async def evaluate_scorecard(scorecard_id: str, pool: Any = Depends(pool_from_request)) -> dict[str, Any]:
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute("SELECT id FROM scorecards WHERE id=%s", (scorecard_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="計分卡不存在")
        cursor = await connection.execute("SELECT service FROM service_catalog ORDER BY service")
        services = await cursor.fetchall()
        evaluated_at = datetime.now(timezone.utc)
        for service in services:
            checks = {"catalog_entry": True, "metrics_scraped": None}
            await connection.execute(
                """INSERT INTO scorecard_results (scorecard_id,service,evaluated_at,checks,passed,total)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (scorecard_id, service["service"], evaluated_at, Jsonb(checks), 1, 2),
            )
    SCORECARD_LAST_EVAL.set(evaluated_at.timestamp())
    return {"scorecard_id": scorecard_id, "evaluated_at": evaluated_at, "services": len(services)}
