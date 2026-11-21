
CREATE TABLE IF NOT EXISTS landing_jobs (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    source_json BLOB NOT NULL,
    state TEXT NOT NULL,
    artifact_json BLOB,
    sealed_artifact_json BLOB,
    provider_evidence_digest TEXT,
    reason_code TEXT,
    revision INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, job_id)
) STRICT;
CREATE TABLE IF NOT EXISTS landing_commands (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    action TEXT NOT NULL,
    command_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, job_id, action, command_key),
    FOREIGN KEY (tenant_id, repository_id, job_id)
      REFERENCES landing_jobs (tenant_id, repository_id, job_id)
) STRICT;
