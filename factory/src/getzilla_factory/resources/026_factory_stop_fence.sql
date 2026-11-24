-- Extend the existing stop history and its existing metrics projection.
-- No operation, task, approval or second stop authority is created here.
LOCK TABLE factory.kill_switches IN ACCESS EXCLUSIVE MODE;
LOCK TABLE factory.kill_switch_heads IN ACCESS EXCLUSIVE MODE;

ALTER TABLE factory.kill_switches ADD COLUMN revision bigint;
CREATE SEQUENCE factory.kill_switch_revision_seq AS bigint MINVALUE 1
  OWNED BY factory.kill_switches.revision;

WITH ordered AS (
  SELECT switch_id,row_number() OVER (ORDER BY created_at,switch_id) AS revision
  FROM factory.kill_switches
)
UPDATE factory.kill_switches current SET revision=ordered.revision
FROM ordered WHERE current.switch_id=ordered.switch_id;

SELECT pg_catalog.setval(
  'factory.kill_switch_revision_seq'::regclass,
  COALESCE((SELECT max(revision) FROM factory.kill_switches),1),
  EXISTS(SELECT 1 FROM factory.kill_switches)
);

ALTER TABLE factory.kill_switches ALTER COLUMN revision SET NOT NULL;
ALTER TABLE factory.kill_switches ADD CONSTRAINT kill_revision_positive CHECK (revision>0);
CREATE UNIQUE INDEX kill_revision_unique ON factory.kill_switches(revision);
CREATE INDEX kill_revision_current ON factory.kill_switches(scope_key,revision DESC);

ALTER TABLE factory.kill_switch_heads ADD COLUMN revision bigint;
UPDATE factory.kill_switch_heads head SET revision=history.revision
FROM factory.kill_switches history WHERE head.switch_id=history.switch_id;
ALTER TABLE factory.kill_switch_heads ALTER COLUMN revision SET NOT NULL;
ALTER TABLE factory.kill_switch_heads ADD CONSTRAINT kill_head_revision_positive CHECK (revision>0);

CREATE FUNCTION factory.assign_kill_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,factory AS $$
BEGIN
  -- Assign only after the same-scope transaction lock. A sequence default would
  -- assign before waiting and could commit an older revision after a newer one.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('getzilla:factory:kill:'||NEW.scope_key,0)
  );
  NEW.revision := pg_catalog.nextval('factory.kill_switch_revision_seq'::regclass);
  RETURN NEW;
END;
$$;

CREATE TRIGGER kill_assign_revision BEFORE INSERT ON factory.kill_switches
  FOR EACH ROW EXECUTE FUNCTION factory.assign_kill_revision();

CREATE OR REPLACE FUNCTION factory.metrics_kill_delta() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,factory AS $$
BEGIN
  INSERT INTO factory.kill_switch_heads(scope_key,switch_id,created_at,enabled,revision)
  VALUES (NEW.scope_key,NEW.switch_id,NEW.created_at,NEW.enabled,NEW.revision)
  ON CONFLICT(scope_key) DO UPDATE SET
    switch_id=EXCLUDED.switch_id,created_at=EXCLUDED.created_at,
    enabled=EXCLUDED.enabled,revision=EXCLUDED.revision
  WHERE EXCLUDED.revision>factory.kill_switch_heads.revision;
  RETURN NULL;
END;
$$;

-- Preserve existing runtime/operator separation. Trigger execution needs no
-- direct function or sequence privilege for the inserting runtime role.
REVOKE ALL ON SEQUENCE factory.kill_switch_revision_seq FROM PUBLIC,factory_runtime;
REVOKE ALL ON FUNCTION factory.assign_kill_revision() FROM PUBLIC,factory_runtime;
REVOKE ALL ON FUNCTION factory.metrics_kill_delta() FROM PUBLIC,factory_runtime;
REVOKE ALL ON factory.kill_switch_heads FROM PUBLIC,factory_runtime;
