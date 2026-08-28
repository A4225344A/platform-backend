CREATE TABLE IF NOT EXISTS approvals (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL,
  service TEXT,
  action TEXT,
  payload JSONB NOT NULL,
  incident_id INT REFERENCES incidents(id),
  trace_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  pr_number INT,
  pr_url TEXT,
  base_commit_sha TEXT,
  requested_by TEXT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
  decided_by TEXT,
  decided_at TIMESTAMPTZ,
  decision_note TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS approvals_dedup
  ON approvals (kind, COALESCE(service, ''), COALESCE(action, ''))
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS approvals_expiring ON approvals (expires_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS scorecards (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  definition JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scorecard_results (
  scorecard_id TEXT NOT NULL REFERENCES scorecards(id) ON DELETE CASCADE,
  service TEXT NOT NULL,
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  checks JSONB NOT NULL,
  passed INT NOT NULL,
  total INT NOT NULL,
  PRIMARY KEY (scorecard_id, service, evaluated_at)
);
INSERT INTO scorecards (id, name, definition)
VALUES ('selfheal-readiness', 'Self-heal readiness', '{"version": 1}'::jsonb)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL,
  verb TEXT NOT NULL,
  object TEXT NOT NULL,
  before JSONB,
  after JSONB,
  trace_id TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_recent ON audit_log (at DESC);
