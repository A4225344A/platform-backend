# EngOps API

獨立的 EngOps 控制平面後端。它聚合既有 W3 Postgres 資料，提供 REST 讀取、日誌目的地提議與計分卡評估觸發；runtime 不呼叫 AWS API，也不具備 Kubernetes 寫入權限。

## 本機執行

需要 Python 3.12+ 與可用的 PostgreSQL。先套用 `migrations/001_engops.sql`，並設定 `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER`、`PGPASSWORD`。

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --reload
```

唯讀端點：`GET /healthz`、`GET /readyz`、`GET /metrics`、`GET /api/v1/overview`、`GET /api/v1/incidents/{id}`。

`POST /api/v1/scorecards/{id}/evaluate` 需要 `Authorization: Bearer $ENGOPS_API_TOKEN`。`POST /api/v1/approvals` 目前是 private/port-forward Lab 路徑，固定寫入 `requested_by=lab-ui`。

Kubernetes/K3s 部署檔已分離到 GitOps repository 的 `platform-gitops/apps/engops-api/`，由 ArgoCD 管理；本 repo 只保留應用程式與資料庫 migration。

## 驗證

```powershell
.venv\Scripts\python -m pytest
```
