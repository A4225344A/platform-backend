import asyncio
import hmac
import os
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
from psycopg.types.json import Jsonb

from .db import REQUIRED_TABLES, create_pool
from .errors import AppError
from .models import ApprovalCreate, Counters, IncidentDetail, NeedYou, Overview
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


def pool_from_request(request: Request) -> Any:
    return request.app.state.db_pool


def require_machine_token(authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("ENGOPS_API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="ENGOPS_API_TOKEN 尚未設定")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授權")


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
                 CASE WHEN kind='policy_change' THEN '/settings/log-sink'
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
