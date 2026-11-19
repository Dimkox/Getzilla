-- Read existing immutable result/semantic evidence without broadening table access.
-- No workflow queue, task ledger, result ledger or eligibility grant is introduced.
CREATE FUNCTION factory.workflow_prerequisite_evidence_v1(
  p_task_id uuid, p_repository_id text, p_source_digest char(64),
  p_spec_digest char(64), p_input_head_sha char(40)
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,factory AS $$
DECLARE proof jsonb;
BEGIN
  SELECT jsonb_build_object(
    'result_digest',trim(w.workspace_result_digest),
    'verdict_digest',trim(v.verdict_digest),
    'packet_digest',trim(p.packet_digest),
    'run_id',r.run_id::text,'fence',r.fence
  ) INTO proof
  FROM factory.tasks t
  JOIN factory.accepted_intents i ON i.intent_id=t.intent_id
  JOIN factory.runs r ON r.run_id=t.current_run_id AND r.task_id=t.task_id
  JOIN factory.execution_packets p ON p.run_id=r.run_id AND p.task_id=t.task_id
  JOIN factory.workspace_results w ON w.run_id=r.run_id AND w.task_id=t.task_id
    AND w.task_packet_digest=p.packet_digest AND w.terminal_stage='completed'
  JOIN factory.semantic_subjects s ON s.workspace_result_digest=w.workspace_result_digest
    AND s.task_id=t.task_id AND s.run_id=r.run_id AND s.fence=r.fence
    AND s.owner_id=r.owner_id AND s.task_packet_digest=p.packet_digest
    AND s.run_manifest_digest=w.run_manifest_digest
    AND s.workspace_snapshot_digest=w.workspace_snapshot_digest
    AND s.exact_head_sha=w.exact_head_sha
  JOIN factory.semantic_verdicts v ON v.subject_digest=s.subject_digest
  WHERE t.task_id=p_task_id AND t.repository_id=p_repository_id
    AND i.source_type='api' AND i.source_id LIKE 'workflow:v1:%'
    AND i.source_digest=p_source_digest AND i.spec_digest=p_spec_digest
    AND t.state NOT IN ('cancelled','superseded','dead')
    AND r.fence=t.current_fence AND r.packet_digest=t.packet_digest
    AND p.legacy_packet_digest=t.packet_digest
    AND p.body->>'legacy_intent_digest'=trim(i.intent_digest)
    AND v.body->>'decision'='pass'
    AND v.body->>'decision_source'='deterministic_adjudicator'
    AND s.input_head_sha=p_input_head_sha
    AND p.body#>>'{authority,exact_head_sha}'=p_input_head_sha
    AND p.body#>>'{authority,spec_digest}'=p_spec_digest
  FOR SHARE OF t,r;
  IF proof IS NOT NULL THEN
    RETURN jsonb_build_object('proof',proof);
  END IF;
  IF EXISTS (SELECT 1 FROM factory.workspace_results WHERE task_id=p_task_id) THEN
    RETURN jsonb_build_object('stale',true);
  END IF;
  RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION factory.workflow_prerequisite_evidence_v1(uuid,text,char,char,char) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION factory.workflow_prerequisite_evidence_v1(uuid,text,char,char,char) TO factory_runtime;
