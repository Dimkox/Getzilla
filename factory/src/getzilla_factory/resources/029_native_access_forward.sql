-- Reuse the canonical protected outbox. A native send cannot be replayed.
ALTER TABLE factory.next_model_request_outbox_v1
  ADD COLUMN native_forward_claimed boolean NOT NULL DEFAULT false;

CREATE FUNCTION factory.claim_native_access_forward_v1(
  p_request char(64),p_envelope char(64),p_binding char(64),p_owner text,p_selection text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o factory.next_model_request_outbox_v1%ROWTYPE; packet jsonb; selection jsonb;
BEGIN
  SELECT * INTO o FROM factory.next_model_request_outbox_v1 WHERE request_digest=p_request FOR UPDATE;
  IF o.request_digest IS NULL OR o.envelope_digest IS DISTINCT FROM p_envelope
    OR o.access_binding_digest IS DISTINCT FROM p_binding OR o.source_grade IS DISTINCT FROM 'protected'
    OR o.access_phase IS DISTINCT FROM 'sending' OR o.state IS DISTINCT FROM 'claimed'
    OR o.native_forward_claimed OR o.observation_deadline<=clock_timestamp()
    OR o.access_binding->>'principal_id' IS DISTINCT FROM p_owner
  THEN RAISE EXCEPTION 'native forward unavailable'; END IF;
  IF factory.access_task_fence_v1(o.task_id,o.run_id,p_owner,o.fence,o.packet_digest)<>o.attempt_id
  THEN RAISE EXCEPTION 'native attempt unavailable'; END IF;
  SELECT body INTO packet FROM factory.execution_packets WHERE packet_digest=o.packet_digest;
  IF p_selection IS NULL OR octet_length(p_selection)>131072 THEN RAISE EXCEPTION 'native profile unavailable'; END IF;
  selection:=p_selection::jsonb;
  IF packet IS NULL OR packet->>'role' IS DISTINCT FROM 'reader'
    OR packet->'provider'->>'provider_id' IS DISTINCT FROM 'qwen'
    OR selection IS DISTINCT FROM jsonb_build_object(
      'provider',packet->'provider','capability_policy',packet->'capability_policy',
      'plan',packet->'plan','workspace_handle',packet->'workspace_handle',
      'prompt_template_digest',packet->'authority'->'prompt_template_digest',
      'role_definition_digest',packet->'authority'->'role_definition_digest',
      'tool_policy_digest',packet->'authority'->'tool_policy_digest',
      'output_schema_digest',packet->'authority'->'output_schema_digest')
  THEN RAISE EXCEPTION 'native profile unavailable'; END IF;
  UPDATE factory.next_model_request_outbox_v1 SET native_forward_claimed=true WHERE request_digest=p_request;
END $$;
REVOKE ALL ON FUNCTION factory.claim_native_access_forward_v1(char(64),char(64),char(64),text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION factory.claim_native_access_forward_v1(char(64),char(64),char(64),text,text) TO factory_runtime;
