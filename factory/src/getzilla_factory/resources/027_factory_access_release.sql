-- Protected first-party sources reuse 024/025 identities. Facts are not permits.
-- Ordinary dispatch cannot claim these rows: their existing dispatch_phase stays blocked.
ALTER TABLE factory.next_model_request_outbox_v1
  ADD COLUMN access_binding jsonb,
  ADD COLUMN access_binding_digest char(64),
  ADD COLUMN access_phase text CHECK (access_phase IN ('prepared','sending','delivered','failed','unknown')),
  ADD COLUMN access_claim char(64),
  ADD CONSTRAINT access_release_binding CHECK (
    (access_binding IS NULL AND access_binding_digest IS NULL AND access_phase IS NULL AND access_claim IS NULL)
    OR (access_binding IS NOT NULL AND access_binding_digest ~ '^[0-9a-f]{64}$'
      AND access_phase IS NOT NULL AND dispatch_phase='blocked'
      AND octet_length(access_binding::text)<=131072
      AND (access_claim IS NULL OR access_claim ~ '^[0-9a-f]{64}$'))
  );

CREATE FUNCTION factory.access_task_fence_v1(p_task uuid,p_run uuid,p_owner text,p_fence bigint,p_packet char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t factory.tasks%ROWTYPE; r factory.runs%ROWTYPE; a uuid; s text;
BEGIN
  IF p_task IS NULL OR p_run IS NULL OR p_owner IS NULL OR p_fence IS NULL OR p_packet IS NULL
    OR p_fence<=0 OR p_packet !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'access task unavailable'; END IF;
  SELECT * INTO r FROM factory.runs WHERE run_id=p_run FOR UPDATE;
  SELECT * INTO t FROM factory.tasks WHERE task_id=p_task FOR UPDATE;
  IF r.run_id IS NULL OR t.task_id IS NULL OR r.task_id<>t.task_id
    OR r.owner_id<>p_owner OR r.fence<>p_fence OR r.packet_digest<>p_packet
    OR t.current_run_id<>r.run_id OR t.current_fence<>r.fence OR r.state<>'leased'
    OR r.lease_expires_at<=clock_timestamp() OR r.deadline_at<=clock_timestamp()
    OR t.state NOT IN ('leased','analyzing','implementing','verifying','reviewing')
  THEN RAISE EXCEPTION 'access task unavailable'; END IF;
  -- Same lock as 026 revision assignment. No source mutex is held during SQL.
  FOR s IN SELECT unnest(ARRAY['global','repository:'||t.repository_id,'task:'||t.task_id::text]) ORDER BY 1 LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('getzilla:factory:kill:'||s,0));
    IF EXISTS (SELECT 1 FROM factory.kill_switch_heads WHERE scope_key=s AND enabled) THEN
      RAISE EXCEPTION 'access task unavailable';
    END IF;
  END LOOP;
  SELECT attempt_id INTO a FROM factory.attempts WHERE task_id=t.task_id AND run_id=r.run_id
    AND finished_at IS NULL ORDER BY attempt_no DESC LIMIT 1 FOR UPDATE;
  IF a IS NULL THEN RAISE EXCEPTION 'access task unavailable'; END IF;
  RETURN a;
END $$;

CREATE FUNCTION factory.stage_access_release_v1(p_envelope char(64),p_owner text,p_binding text,p_digest char(64))
RETURNS char(64) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s factory.result_sources_v1%ROWTYPE; b jsonb; d char(64);
BEGIN
  IF p_binding IS NULL OR p_digest IS NULL OR p_envelope IS NULL OR p_owner IS NULL
    OR octet_length(p_binding)>131072 OR p_digest !~ '^[0-9a-f]{64}$'
    OR factory.execution_contract_hash(NULL,p_binding)<>p_digest THEN
    RAISE EXCEPTION 'invalid access binding'; END IF;
  b:=p_binding::jsonb;
  IF factory.execution_canonical_json(b)<>p_binding OR jsonb_typeof(b)<>'object'
    OR NOT b ?& ARRAY['contract','execution_packet_digest','authority_revision','permission_digest',
      'destination_id','destination_revision','lineage','transform','payload_digest','principal_id']
    OR (SELECT count(*) FROM jsonb_object_keys(b))<>10
    OR b->>'contract'<>'factory-owned-access-release/v1'
    OR jsonb_typeof(b->'lineage')<>'array' OR jsonb_array_length(b->'lineage') NOT BETWEEN 1 AND 128
    OR b->>'authority_revision' !~ '^[1-9][0-9]*$' OR b->>'destination_revision' !~ '^[1-9][0-9]*$'
    OR b->>'permission_digest' !~ '^[0-9a-f]{64}$' OR b->>'payload_digest' !~ '^[0-9a-f]{64}$'
    OR b->>'execution_packet_digest' !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'invalid access binding'; END IF;
  SELECT * INTO s FROM factory.result_sources_v1 WHERE envelope_digest=p_envelope;
  IF s.envelope_digest IS NULL OR s.outcome NOT IN ('allow','redacted')
    OR s.envelope->>'sanitized_payload_digest'<>b->>'payload_digest'
  THEN RAISE EXCEPTION 'access result unavailable'; END IF;
  IF factory.access_task_fence_v1(s.task_id,s.run_id,p_owner,s.fence,s.packet_digest)<>s.attempt_id
  THEN RAISE EXCEPTION 'access attempt unavailable'; END IF;
  d:=factory.execution_contract_hash(NULL,'factory-access-release:'||trim(p_envelope)||':'||trim(p_digest));
  INSERT INTO factory.next_model_request_outbox_v1(request_digest,envelope_digest,task_id,run_id,attempt_id,
    repository_id,fence,packet_digest,dispatch_phase,operation_id,observation_deadline,
    reason_code,access_binding,access_binding_digest,access_phase)
  VALUES(d,s.envelope_digest,s.task_id,s.run_id,s.attempt_id,s.repository_id,s.fence,s.packet_digest,
    'blocked','factory-result:'||trim(d),clock_timestamp()+interval '2 seconds',
    'protected_native_queue',b,p_digest,'prepared');
  RETURN d;
END $$;

CREATE FUNCTION factory.claim_access_release_v1(p_request char(64),p_binding char(64),p_owner text,p_claim char(64))
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o factory.next_model_request_outbox_v1%ROWTYPE;
BEGIN
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE request_digest=p_request FOR UPDATE;
  IF o.access_phase IS DISTINCT FROM 'prepared' OR o.access_binding_digest IS DISTINCT FROM p_binding
    OR p_claim IS NULL OR p_claim !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'access release unavailable'; END IF;
  PERFORM factory.access_task_fence_v1(o.task_id,o.run_id,p_owner,o.fence,o.packet_digest);
  UPDATE factory.next_model_request_outbox_v1 SET access_phase='sending',access_claim=p_claim,
    state='claimed',send_started_at=clock_timestamp(),send_attempts=send_attempts+1
    WHERE request_digest=p_request;
END $$;

CREATE FUNCTION factory.observe_access_release_v1(p_request char(64),p_claim char(64),p_state text,p_observation char(64))
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF p_state IS NULL OR p_state NOT IN ('delivered','failed','unknown')
    OR (p_state='delivered') IS DISTINCT FROM (p_observation IS NOT NULL)
    OR (p_observation IS NOT NULL AND p_observation !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'invalid access observation'; END IF;
  UPDATE factory.next_model_request_outbox_v1 SET access_phase=p_state,
    state=CASE WHEN p_state='unknown' THEN 'claimed' ELSE p_state END,
    observation_digest=p_observation,observed_at=clock_timestamp()
  WHERE request_digest=p_request AND access_phase='sending' AND access_claim=p_claim;
  IF NOT FOUND THEN RAISE EXCEPTION 'access observation unavailable'; END IF;
END $$;

REVOKE ALL ON FUNCTION factory.access_task_fence_v1(uuid,uuid,text,bigint,char(64)) FROM PUBLIC;
REVOKE ALL ON FUNCTION factory.stage_access_release_v1(char(64),text,text,char(64)) FROM PUBLIC;
REVOKE ALL ON FUNCTION factory.claim_access_release_v1(char(64),char(64),text,char(64)) FROM PUBLIC;
REVOKE ALL ON FUNCTION factory.observe_access_release_v1(char(64),char(64),text,char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION factory.access_task_fence_v1(uuid,uuid,text,bigint,char(64)),
  factory.stage_access_release_v1(char(64),text,text,char(64)),
  factory.claim_access_release_v1(char(64),char(64),text,char(64)),
  factory.observe_access_release_v1(char(64),char(64),text,char(64)) TO factory_runtime;
