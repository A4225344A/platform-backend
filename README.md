# EngOps API

獨立的 EngOps 控制平面後端。它聚合既有 W3 Postgres 資料，提供 REST 讀取、日誌目的地提議與計分卡評估觸發；runtime 不呼叫 AWS API，也不具備 Kubernetes 寫入權限。

## 本機執行

需要 Python 3.12+ 與可用的 PostgreSQL。先套用 `migrations/001_engops.sql`,並設定 `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER`、`PGPASSWORD`。

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.lock
.venv\Scripts\python -m uvicorn app.main:app --reload
```

`requirements.lock` 是從 `requirements.in` 用 pip-tools 產生的雜湊鎖定檔;改依賴版本時改 `requirements.in`。

**不要在本機(尤其是 Windows)重新產生這個檔案。** `Dockerfile`/CI 跑在 Linux + Python 3.12,pip-compile 是「在執行它的那台機器上」解析依賴——Windows 上會多解析出 Windows 專屬套件(`colorama`、`tzdata`),漏掉 Linux 專屬的 `uvloop`,產生出的鎖定檔在本機測試全過,只有 CI 重新解析比對時才會炸,而且炸的方式很難聯想到「作業系統不同」。

改依賴後,推上去,再手動觸發 `.github/workflows/sync-requirements-lock.yml`(Actions 分頁 → Sync requirements.lock → Run workflow)——它在跟 `Dockerfile` 完全一致的 Linux + Python 3.12 環境重新產生並自動 commit 回來。

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.lock
.venv\Scripts\python -m pip check
.venv\Scripts\python -m pip install pip-audit==2.10.1
.venv\Scripts\python -m pip_audit -r requirements.lock
```

唯讀端點：`GET /healthz`、`GET /readyz`、`GET /metrics`、`GET /api/v1/overview`、`GET /api/v1/incidents/{id}`。

`POST /api/v1/scorecards/{id}/evaluate` 需要 `Authorization: Bearer $ENGOPS_API_TOKEN`。`POST /api/v1/approvals` 目前是 private/port-forward Lab 路徑；`requested_by` 可由呼叫端傳入（未帶時預設 `lab-ui`），尚未有真正的登入身分驗證，`requested_by`/`decided_by` 目前仍是未經驗證的自由輸入字串。

Kubernetes/K3s 部署檔已分離到 GitOps repository 的 `platform-gitops/apps/engops-api/`，由 ArgoCD 管理；本 repo 只保留應用程式與資料庫 migration。

## 驗證

```powershell
.venv\Scripts\python -m pytest
```
