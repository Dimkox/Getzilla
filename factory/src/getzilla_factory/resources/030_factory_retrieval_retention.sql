-- Retire owned retrieval derivatives without rewriting their original identities.
-- Existing result/outbox rows remain the only admission and retirement journal.
ALTER TABLE factory.result_sources_v1
  ADD COLUMN payload_retired_at timestamptz,
  ADD COLUMN retired_projection_sha256 char(64),
  ADD COLUMN payload_retirement_reason text,
  ADD CONSTRAINT result_retirement_projection CHECK (
    (payload_retired_at IS NULL AND retired_projection_sha256 IS NULL AND payload_retirement_reason IS NULL)
    OR (payload_retired_at IS NOT NULL AND retired_projection_sha256 IS NOT NULL
      AND retired_projection_sha256 ~ '^[0-9a-f]{64}$' AND payload_retirement_reason IS NOT NULL
      AND payload_retirement_reason IN ('source_deleted','retention_expired','operator_retire')));

ALTER TABLE factory.next_model_request_outbox_v1
  ADD COLUMN access_destination_identity jsonb,
  ADD COLUMN retrieval_retention_profile text,
  ADD COLUMN retrieval_capture_at timestamptz,
  ADD COLUMN retrieval_retire_after timestamptz,
  ADD COLUMN retirement_scope jsonb,
  ADD COLUMN retired_access_binding_sha256 char(64),
  ADD COLUMN retirement_state text CHECK (retirement_state IN ('sending','confirmed','unknown')),
  ADD COLUMN retirement_claim char(64),
  ADD COLUMN retirement_request_digest char(64),
  ADD COLUMN retirement_actor text,
  ADD COLUMN retirement_deadline timestamptz,
  ADD COLUMN retirement_last_observed_at timestamptz,
  ADD COLUMN retirement_observation_digest char(64),
  ADD CONSTRAINT access_retirement_state CHECK (
    (retirement_state IS NULL AND retirement_claim IS NULL AND retirement_request_digest IS NULL
      AND retirement_actor IS NULL AND retirement_deadline IS NULL AND retirement_scope IS NULL
      AND retirement_observation_digest IS NULL AND retired_access_binding_sha256 IS NULL)
    OR (retirement_state IS NOT NULL AND retirement_claim IS NOT NULL AND retirement_claim ~ '^[0-9a-f]{64}$'
      AND retirement_request_digest IS NOT NULL AND retirement_request_digest ~ '^[0-9a-f]{64}$' AND retirement_deadline IS NOT NULL
      AND retirement_actor IS NOT NULL AND octet_length(retirement_actor) BETWEEN 1 AND 128
      AND retirement_scope IS NOT NULL AND jsonb_typeof(retirement_scope)='object'
      AND retired_access_binding_sha256 IS NOT NULL AND retired_access_binding_sha256 ~ '^[0-9a-f]{64}$'
      AND (retirement_state='confirmed') IS NOT DISTINCT FROM (retirement_observation_digest IS NOT NULL)));
ALTER TABLE factory.next_model_request_outbox_v1 ADD CONSTRAINT retrieval_capture_lifetime CHECK (
  (retrieval_retention_profile IS NULL AND retrieval_capture_at IS NULL AND retrieval_retire_after IS NULL)
  OR (retrieval_retention_profile IS NOT NULL AND retrieval_retention_profile='factory.ephemeral-retrieval162/v1'
    AND retrieval_capture_at IS NOT NULL AND retrieval_retire_after IS NOT NULL
    AND retrieval_retire_after>retrieval_capture_at
    AND retrieval_retire_after<=retrieval_capture_at+interval '2 seconds'));
CREATE INDEX retrieval_expiry_due ON factory.next_model_request_outbox_v1(retrieval_retire_after,request_digest)
  WHERE retrieval_retention_profile='factory.ephemeral-retrieval162/v1';

CREATE FUNCTION factory.guard_retired_result_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF OLD.payload_retired_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'retired result is immutable'; END IF;
  IF OLD.payload_retired_at IS NOT NULL THEN RETURN NEW; END IF;
  IF NEW.payload_retired_at IS NOT NULL AND (
    jsonb_typeof(NEW.envelope) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(NEW.envelope))<>4
    OR NEW.envelope->>'contract' IS DISTINCT FROM 'factory-retired-result/v1'
    OR NEW.envelope->>'original_envelope_digest' IS DISTINCT FROM trim(OLD.envelope_digest)
    OR NEW.envelope->>'original_payload_digest' IS DISTINCT FROM OLD.envelope->>'sanitized_payload_digest'
    OR NEW.envelope->>'source_digest' IS DISTINCT FROM trim(OLD.source_digest)
    OR NEW.envelope ? 'sanitized_payload'
    OR NEW.retired_projection_sha256 IS DISTINCT FROM
      factory.execution_contract_hash(NULL,factory.execution_canonical_json(NEW.envelope))) THEN
    RAISE EXCEPTION 'invalid retired result projection'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER result_retirement_guard BEFORE UPDATE ON factory.result_sources_v1
  FOR EACH ROW EXECUTE FUNCTION factory.guard_retired_result_v1();

-- Preserve027's immutable grade/source facts. The sole new transition is the
-- explicitly validated first retirement projection; no ordinary update opens.
CREATE OR REPLACE FUNCTION factory.stamp_result_access_grade_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW IS DISTINCT FROM OLD AND NOT (
      OLD.access_grade='protected' AND OLD.payload_retired_at IS NULL AND NEW.payload_retired_at IS NOT NULL
      AND (to_jsonb(NEW)-ARRAY['envelope','payload_retired_at','retired_projection_sha256','payload_retirement_reason'])
        =(to_jsonb(OLD)-ARRAY['envelope','payload_retired_at','retired_projection_sha256','payload_retirement_reason']))
      THEN RAISE EXCEPTION 'immutable result source'; END IF;
  ELSE
    NEW.access_grade:=CASE WHEN NEW.source_operation LIKE 'access:%'
      OR NEW.envelope->>'policy_version' LIKE 'access-local-%' THEN 'protected' ELSE 'ordinary' END;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION factory.guard_retired_outbox_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF NEW.retrieval_retention_profile='factory.ephemeral-retrieval162/v1' AND NEW.access_phase='sending'
    AND (NEW.retrieval_retire_after IS NULL OR clock_timestamp()>=NEW.retrieval_retire_after
      OR clock_timestamp()<NEW.retrieval_capture_at) THEN
    RAISE EXCEPTION 'retrieval capture expired'; END IF;
  IF EXISTS (SELECT 1 FROM factory.result_sources_v1 s WHERE s.envelope_digest=NEW.envelope_digest
      AND s.payload_retired_at IS NOT NULL)
    AND (NEW.access_phase IN ('prepared','sending') OR NEW.dispatch_phase IN ('pending','claimed','sending')) THEN
    RAISE EXCEPTION 'retired result cannot be dispatched'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER outbox_retirement_guard BEFORE INSERT OR UPDATE ON factory.next_model_request_outbox_v1
  FOR EACH ROW EXECUTE FUNCTION factory.guard_retired_outbox_v1();

-- This existing row is also the source-bound retirement/audit record. Do not
-- prune it into an unprovable orphan while keeping the immutable source row.
CREATE FUNCTION factory.keep_retrieval_retirement_record_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF OLD.source_grade='protected' AND (OLD.access_destination_identity IS NOT NULL
      OR OLD.retirement_state IS NOT NULL) THEN
    RAISE EXCEPTION 'retrieval retirement record is retained'; END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER keep_retrieval_retirement_record BEFORE DELETE ON factory.next_model_request_outbox_v1
  FOR EACH ROW EXECUTE FUNCTION factory.keep_retrieval_retirement_record_v1();

CREATE OR REPLACE FUNCTION factory.stamp_outbox_access_grade_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    SELECT access_grade INTO NEW.source_grade FROM factory.result_sources_v1
      WHERE envelope_digest=NEW.envelope_digest;
    IF NEW.source_grade IS NULL THEN RAISE EXCEPTION 'result source unavailable'; END IF;
  ELSE
    IF NEW.source_grade IS DISTINCT FROM OLD.source_grade OR NEW.envelope_digest IS DISTINCT FROM OLD.envelope_digest
      OR NEW.access_binding_digest IS DISTINCT FROM OLD.access_binding_digest
      OR (OLD.access_destination_identity IS NOT NULL
        AND NEW.access_destination_identity IS DISTINCT FROM OLD.access_destination_identity)
      THEN RAISE EXCEPTION 'immutable result provenance'; END IF;
    IF OLD.retrieval_retention_profile IS NOT NULL AND (
      NEW.retrieval_retention_profile IS DISTINCT FROM OLD.retrieval_retention_profile
      OR NEW.retrieval_capture_at IS DISTINCT FROM OLD.retrieval_capture_at
      OR NEW.retrieval_retire_after IS DISTINCT FROM OLD.retrieval_retire_after)
      THEN RAISE EXCEPTION 'immutable capture lifetime'; END IF;
    IF NEW.access_binding IS DISTINCT FROM OLD.access_binding AND (
      OLD.source_grade='protected' AND OLD.retirement_state IS NULL AND NEW.retirement_state='sending'
      AND EXISTS (SELECT 1 FROM factory.result_sources_v1 s WHERE s.envelope_digest=NEW.envelope_digest
        AND s.payload_retired_at IS NOT NULL)
      AND NEW.access_binding->>'contract'='factory-retired-access-binding/v1'
      AND (SELECT count(*) FROM jsonb_object_keys(NEW.access_binding))=3
      AND NEW.access_binding->>'original_binding_digest'=trim(OLD.access_binding_digest)
      AND NEW.access_binding->'dependency_digests'=(SELECT jsonb_agg(
        factory.execution_contract_hash(NULL,factory.execution_canonical_json(item)))
        FROM jsonb_array_elements(OLD.access_binding->'lineage') item)
      AND NEW.retired_access_binding_sha256=factory.execution_contract_hash(NULL,
        factory.execution_canonical_json(NEW.access_binding))) IS NOT TRUE
      THEN RAISE EXCEPTION 'immutable result provenance'; END IF;
    IF OLD.retirement_state IS NOT NULL AND (
      NEW.retirement_scope IS DISTINCT FROM OLD.retirement_scope
      OR NEW.retirement_claim IS DISTINCT FROM OLD.retirement_claim
      OR NEW.retirement_request_digest IS DISTINCT FROM OLD.retirement_request_digest
      OR NEW.retirement_actor IS DISTINCT FROM OLD.retirement_actor
      OR NEW.retirement_deadline IS DISTINCT FROM OLD.retirement_deadline
      OR NEW.retired_access_binding_sha256 IS DISTINCT FROM OLD.retired_access_binding_sha256)
      THEN RAISE EXCEPTION 'immutable retirement identity'; END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION factory.bind_access_destination_v1(p_request char(64),p_binding char(64),p_identity text,
  p_profile text DEFAULT NULL,p_captured double precision DEFAULT NULL,p_due double precision DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o factory.next_model_request_outbox_v1%ROWTYPE; b jsonb; payload jsonb;
BEGIN
  IF p_identity IS NULL OR octet_length(p_identity)>1024 THEN RAISE EXCEPTION 'invalid destination identity'; END IF;
  b:=p_identity::jsonb;
  IF factory.execution_canonical_json(b)<>p_identity OR jsonb_typeof(b)<>'object'
    OR (SELECT count(*) FROM jsonb_object_keys(b))<>3 OR NOT b ?& ARRAY['kind','device','inode']
    OR b->>'kind' IS DISTINCT FROM 'uds' OR jsonb_typeof(b->'device')<>'number' OR jsonb_typeof(b->'inode')<>'number'
    OR b->>'device' !~ '^[0-9]{1,20}$' OR b->>'inode' !~ '^[0-9]{1,20}$'
    THEN RAISE EXCEPTION 'invalid destination identity'; END IF;
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE request_digest=p_request FOR UPDATE;
  IF o.source_grade IS DISTINCT FROM 'protected' OR o.access_phase IS DISTINCT FROM 'prepared'
    OR o.access_binding_digest IS DISTINCT FROM p_binding OR o.retirement_state IS NOT NULL
    OR (o.access_destination_identity IS NOT NULL AND o.access_destination_identity<>b)
    THEN RAISE EXCEPTION 'destination binding unavailable'; END IF;
  IF p_profile IS NULL THEN
    IF p_captured IS NOT NULL OR p_due IS NOT NULL THEN RAISE EXCEPTION 'invalid capture lifetime'; END IF;
  ELSE
    IF p_profile<>'factory.ephemeral-retrieval162/v1' OR p_captured IS NULL OR p_due IS NULL
      OR p_captured NOT BETWEEN 0 AND 253402300799 OR p_due NOT BETWEEN 0 AND 253402300799
      OR NOT p_due>p_captured OR p_due-p_captured>2
      OR to_timestamp(p_captured)>clock_timestamp() OR to_timestamp(p_due)<=clock_timestamp()
      THEN RAISE EXCEPTION 'invalid capture lifetime'; END IF;
    SELECT (envelope->>'sanitized_payload')::jsonb INTO payload FROM factory.result_sources_v1
      WHERE envelope_digest=o.envelope_digest;
    IF payload->>'contract' IS DISTINCT FROM p_profile
      OR payload->'retention'->>'profile' IS DISTINCT FROM p_profile
      OR (payload->'retention'->>'captured_at')::double precision IS DISTINCT FROM p_captured
      OR (payload->'retention'->>'due_at')::double precision IS DISTINCT FROM p_due
      THEN RAISE EXCEPTION 'capture lifetime binding unavailable'; END IF;
  END IF;
  IF o.access_destination_identity IS NOT NULL THEN
    IF o.retrieval_retention_profile IS DISTINCT FROM p_profile THEN RAISE EXCEPTION 'capture lifetime changed'; END IF;
    RETURN; -- Exact identity replay never renews an existing absolute deadline.
  END IF;
  UPDATE factory.next_model_request_outbox_v1 SET access_destination_identity=b,
    retrieval_retention_profile=p_profile,retrieval_capture_at=to_timestamp(p_captured),
    retrieval_retire_after=to_timestamp(p_due) WHERE request_digest=p_request;
END $$;

CREATE FUNCTION factory.access_retirement_metadata_v1(p_envelope char(64)) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s factory.result_sources_v1%ROWTYPE; o factory.next_model_request_outbox_v1%ROWTYPE;
  b jsonb; scope jsonb;
BEGIN
  SELECT * INTO s FROM factory.result_sources_v1 WHERE envelope_digest=p_envelope;
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE envelope_digest=p_envelope;
  IF s.access_grade IS DISTINCT FROM 'protected' OR o.source_grade IS DISTINCT FROM 'protected'
    OR o.request_digest IS NULL OR o.access_destination_identity IS NULL
    THEN RAISE EXCEPTION 'retrieval result unavailable'; END IF;
  IF s.payload_retired_at IS NULL THEN
    b:=(s.envelope->>'sanitized_payload')::jsonb;
    IF (b->>'contract' IN ('factory.local-retrieval162/v1','factory.ephemeral-retrieval162/v1')) IS NOT TRUE
      OR jsonb_typeof(o.access_binding->'lineage') IS DISTINCT FROM 'array'
      OR jsonb_array_length(o.access_binding->'lineage') NOT BETWEEN 1 AND 128
      THEN RAISE EXCEPTION 'retrieval result unavailable'; END IF;
    scope:=jsonb_build_object('tenant_id',o.access_binding->'lineage'->0->0->>0,
      'project_id',o.access_binding->'lineage'->0->0->>1,'repository_id',s.repository_id,
      'destination_id',o.access_binding->>'destination_id',
      'destination_revision',o.access_binding->'destination_revision');
  ELSE scope:=o.retirement_scope; END IF;
  RETURN jsonb_build_object('envelope_digest',trim(s.envelope_digest),'request_digest',trim(o.request_digest),
    'operation_id',o.operation_id,'scope',scope,'destination_identity',o.access_destination_identity,
    'retirement_state',o.retirement_state,'retirement_claim',trim(o.retirement_claim),
    'retirement_request_digest',trim(o.retirement_request_digest),'local_retired',s.payload_retired_at IS NOT NULL,
    'retention_profile',o.retrieval_retention_profile,
    'captured_at',extract(epoch FROM o.retrieval_capture_at),'due_at',extract(epoch FROM o.retrieval_retire_after),
    'cleanup_delay_seconds',CASE WHEN o.retrieval_retire_after IS NULL THEN NULL
      ELSE greatest(0,extract(epoch FROM (coalesce(s.payload_retired_at,clock_timestamp())-o.retrieval_retire_after))) END,
    'clock_valid',CASE WHEN o.retrieval_capture_at IS NULL THEN NULL ELSE clock_timestamp()>=o.retrieval_capture_at END,
    'dependency_digests',CASE WHEN s.payload_retired_at IS NOT NULL THEN o.access_binding->'dependency_digests'
      ELSE (SELECT jsonb_agg(factory.execution_contract_hash(NULL,factory.execution_canonical_json(item)))
        FROM jsonb_array_elements(o.access_binding->'lineage') item) END);
END $$;

CREATE FUNCTION factory.expire_access_result_v1(p_envelope char(64),p_claim char(64)) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o factory.next_model_request_outbox_v1%ROWTYPE; m jsonb;
BEGIN
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE envelope_digest=p_envelope FOR UPDATE;
  IF o.retrieval_retention_profile IS DISTINCT FROM 'factory.ephemeral-retrieval162/v1'
    OR o.retrieval_capture_at IS NULL OR o.retrieval_retire_after IS NULL
    OR (clock_timestamp()<o.retrieval_retire_after AND clock_timestamp()>=o.retrieval_capture_at)
    THEN RAISE EXCEPTION 'capture has not expired'; END IF;
  m:=factory.access_retirement_metadata_v1(p_envelope);
  RETURN factory.retire_access_result_v1(p_envelope,factory.execution_canonical_json(m->'scope'),
    'lifecycle:retrieval162/v1','retention_expired',p_claim);
END $$;

CREATE FUNCTION factory.retire_access_result_v1(p_envelope char(64),p_scope text,p_actor text,p_reason text,p_claim char(64))
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s factory.result_sources_v1%ROWTYPE; o factory.next_model_request_outbox_v1%ROWTYPE;
  m jsonb; projection jsonb; binding_projection jsonb;
BEGIN
  IF p_actor IS NULL OR octet_length(p_actor) NOT BETWEEN 1 AND 128 OR p_claim IS NULL
    OR p_claim !~ '^[0-9a-f]{64}$' OR p_reason NOT IN ('source_deleted','retention_expired','operator_retire')
    OR p_reason IS NULL OR p_scope IS NULL OR octet_length(p_scope)>2048
    THEN RAISE EXCEPTION 'invalid retirement request'; END IF;
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE envelope_digest=p_envelope FOR UPDATE;
  SELECT * INTO s FROM factory.result_sources_v1 WHERE envelope_digest=p_envelope FOR UPDATE;
  m:=factory.access_retirement_metadata_v1(p_envelope);
  IF factory.execution_canonical_json(m->'scope')<>p_scope THEN RAISE EXCEPTION 'retirement scope changed'; END IF;
  IF o.retirement_state IS NOT NULL THEN RETURN m||jsonb_build_object('dispatch_allowed',false); END IF;
  projection:=jsonb_build_object('contract','factory-retired-result/v1',
    'original_envelope_digest',trim(s.envelope_digest),
    'original_payload_digest',s.envelope->>'sanitized_payload_digest','source_digest',trim(s.source_digest));
  binding_projection:=jsonb_build_object('contract','factory-retired-access-binding/v1',
    'original_binding_digest',trim(o.access_binding_digest),
    'dependency_digests',(SELECT jsonb_agg(factory.execution_contract_hash(NULL,factory.execution_canonical_json(item)))
      FROM jsonb_array_elements(o.access_binding->'lineage') item));
  UPDATE factory.result_sources_v1 SET envelope=projection,payload_retired_at=clock_timestamp(),
    retired_projection_sha256=factory.execution_contract_hash(NULL,factory.execution_canonical_json(projection)),
    payload_retirement_reason=p_reason WHERE envelope_digest=p_envelope;
  UPDATE factory.next_model_request_outbox_v1 SET retirement_scope=m->'scope',retirement_state='sending',
    retirement_claim=p_claim,retirement_actor=p_actor,retirement_deadline=clock_timestamp()+interval '2 seconds',
    retirement_request_digest=factory.execution_contract_hash(NULL,'factory-retrieval-retirement:'||trim(p_envelope)),
    access_phase=CASE WHEN access_phase='prepared' THEN 'failed' WHEN access_phase='sending' THEN 'unknown' ELSE access_phase END,
    state=CASE WHEN access_phase='prepared' THEN 'failed' ELSE state END,
    access_binding=binding_projection,
    retired_access_binding_sha256=factory.execution_contract_hash(NULL,factory.execution_canonical_json(binding_projection))
    WHERE envelope_digest=p_envelope;
  RETURN factory.access_retirement_metadata_v1(p_envelope)||jsonb_build_object('dispatch_allowed',true);
END $$;

CREATE FUNCTION factory.observe_access_retirement_v1(p_envelope char(64),p_claim char(64),p_state text,p_observation char(64))
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o factory.next_model_request_outbox_v1%ROWTYPE; expected char(64);
BEGIN
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE envelope_digest=p_envelope FOR UPDATE;
  expected:=factory.execution_contract_hash(NULL,factory.execution_canonical_json(jsonb_build_object(
    'contract','factory-result-retirement-postcondition/v1','operation_id',o.operation_id,
    'request_digest',trim(o.request_digest),'envelope_digest',trim(o.envelope_digest),
    'retirement_request_digest',trim(o.retirement_request_digest))));
  IF o.retirement_claim IS DISTINCT FROM p_claim OR o.retirement_state IS NULL
    OR p_state IS NULL OR p_state NOT IN ('unknown','confirmed')
    OR (p_state='confirmed') IS DISTINCT FROM (p_observation IS NOT NULL)
    OR (p_state='confirmed' AND p_observation IS DISTINCT FROM expected)
    THEN RAISE EXCEPTION 'retirement observation unavailable'; END IF;
  IF o.retirement_state='confirmed' AND p_state<>'confirmed' THEN RETURN; END IF;
  UPDATE factory.next_model_request_outbox_v1 SET retirement_state=p_state,
    retirement_observation_digest=p_observation,retirement_last_observed_at=clock_timestamp()
    WHERE envelope_digest=p_envelope;
END $$;

REVOKE ALL ON FUNCTION factory.guard_retired_result_v1(),factory.guard_retired_outbox_v1(),
  factory.keep_retrieval_retirement_record_v1(),
  factory.bind_access_destination_v1(char(64),char(64),text,text,double precision,double precision),
  factory.access_retirement_metadata_v1(char(64)),factory.expire_access_result_v1(char(64),char(64)),
  factory.retire_access_result_v1(char(64),text,text,text,char(64)),
  factory.observe_access_retirement_v1(char(64),char(64),text,char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION factory.bind_access_destination_v1(char(64),char(64),text,text,double precision,double precision),
  factory.expire_access_result_v1(char(64),char(64)),
  factory.access_retirement_metadata_v1(char(64)),factory.retire_access_result_v1(char(64),text,text,text,char(64)),
  factory.observe_access_retirement_v1(char(64),char(64),text,char(64)) TO factory_runtime;
