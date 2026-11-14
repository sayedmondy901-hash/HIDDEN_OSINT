-- Educational prototype. Run only on a local development machine.
-- For production, use a secrets manager and stronger unique passwords.

CREATE ROLE backend_app LOGIN PASSWORD 'change_backend_password';
CREATE ROLE worker_app LOGIN PASSWORD 'change_worker_password';

CREATE TABLE scan_tasks (
    id BIGSERIAL PRIMARY KEY,
    owner_id TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE findings (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    source TEXT NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (task_id, subdomain, source)
);

CREATE INDEX idx_scan_tasks_owner_created ON scan_tasks(owner_id, created_at DESC);
CREATE INDEX idx_findings_task_id ON findings(task_id);

-- Backend can create tasks and read tasks/results.
GRANT CONNECT ON DATABASE osint_db TO backend_app;
GRANT USAGE ON SCHEMA public TO backend_app;
GRANT SELECT, INSERT ON scan_tasks TO backend_app;
GRANT SELECT ON findings TO backend_app;
GRANT USAGE, SELECT ON SEQUENCE scan_tasks_id_seq TO backend_app;

-- Worker can read tasks, update only task status/timing/error fields,
-- and insert findings. It cannot read or change user account data.
GRANT CONNECT ON DATABASE osint_db TO worker_app;
GRANT USAGE ON SCHEMA public TO worker_app;
GRANT SELECT ON scan_tasks TO worker_app;
GRANT UPDATE (status, started_at, finished_at, error_message) ON scan_tasks TO worker_app;
GRANT INSERT ON findings TO worker_app;
GRANT USAGE, SELECT ON SEQUENCE findings_id_seq TO worker_app;
