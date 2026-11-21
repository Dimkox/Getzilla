
CREATE TABLE shared_control_bindings (
 tenant_id TEXT NOT NULL, repository_id TEXT NOT NULL, job_id TEXT NOT NULL,
 binding BLOB NOT NULL, PRIMARY KEY(tenant_id,repository_id,job_id),
 FOREIGN KEY(tenant_id,repository_id,job_id) REFERENCES landing_jobs(tenant_id,repository_id,job_id)
) STRICT;
CREATE TABLE shared_control_clock (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), highwater REAL NOT NULL) STRICT;
