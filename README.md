# EngOps API

獨立的 EngOps 控制平面後端。它聚合既有 W3 Postgres 資料，提供 REST 讀取、日誌目的地提議與計分卡評估觸發；runtime 不呼叫 AWS API，也不具備 Kubernetes 寫入權限。

## 本機執行

需要 Python 3.12+ 與可用的 PostgreSQL。先套用 `migrations/001_engops.sql`,並設定 `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER`、`PGPASSWORD`。

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.lock
.venv\Scripts\python -m uvicorn app.main:app --reload
```

`requirements.lock` 是從 `requirements.in` 用 pip-tools 產生的雜湊鎖定檔;改依賴版本時改 `requirements.in`,再重新產生。**務必用 Python 3.12 產生**(跟 `Dockerfile`/CI 的 `python-version: "3.12"` 一致)——曾經誤用本機裝的 Python 3.14 產生過一次,解析出的傳遞依賴（`typing-extensions` 的 `via` 清單)跟 3.12 環境不同,導致 CI 的 `git diff --exit-code requirements.lock` 判定「lock 檔不是最新」而失敗。用錯 Python 版本產生的 lock 檔本機測試會全過,只有在 CI 重新解析比對時才會爆炸,不容易在本機發現:

```powershell
py -3.12 -m venv .venv312
.venv312\Scripts\python -m pip install --upgrade pip-tools==7.6.1 pip-audit==2.10.1
.venv312\Scripts\python -m piptools compile --generate-hashes --strip-extras --no-header --output-file requirements.lock requirements.in
.venv312\Scripts\python -m pip install --require-hashes -r requirements.lock
.venv312\Scripts\python -m pip check
.venv312\Scripts\python -m pip_audit -r requirements.lock
```

唯讀端點：`GET /healthz`、`GET /readyz`、`GET /metrics`、`GET /api/v1/overview`、`GET /api/v1/incidents/{id}`。

`POST /api/v1/scorecards/{id}/evaluate` 需要 `Authorization: Bearer $ENGOPS_API_TOKEN`。`POST /api/v1/approvals` 目前是 private/port-forward Lab 路徑；`requested_by` 可由呼叫端傳入（未帶時預設 `lab-ui`），尚未有真正的登入身分驗證，`requested_by`/`decided_by` 目前仍是未經驗證的自由輸入字串。

Kubernetes/K3s 部署檔已分離到 GitOps repository 的 `platform-gitops/apps/engops-api/`，由 ArgoCD 管理；本 repo 只保留應用程式與資料庫 migration。

## 驗證

```powershell
.venv\Scripts\python -m pytest
```
