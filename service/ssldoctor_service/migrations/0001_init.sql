-- 0001: tenancy, agents, targets, scan jobs, immutable results.
-- Runs as an administrative role. Tables are owned by ssldoctor_owner
-- (NOLOGIN). The application connects as ssldoctor_app, which is subject to
-- row-level security on every tenant table.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ssldoctor_owner') THEN
        CREATE ROLE ssldoctor_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ssldoctor_app') THEN
        CREATE ROLE ssldoctor_app LOGIN NOBYPASSRLS;
    END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION ssldoctor_owner;
GRANT USAGE ON SCHEMA app TO ssldoctor_app;
SET ROLE ssldoctor_owner;

-- Tenant id of the current transaction (NULL when unset -> no rows match).
CREATE FUNCTION app.current_org() RETURNS uuid LANGUAGE sql STABLE AS
    $$ SELECT NULLIF(current_setting('app.org_id', true), '')::uuid $$;

CREATE TABLE app.organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.api_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    name        text NOT NULL,
    token_hash  text NOT NULL UNIQUE,          -- sha256 hex; token never stored
    role        text NOT NULL CHECK (role IN ('owner','admin','engineer','viewer')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

CREATE TABLE app.enrollment_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    token_hash  text NOT NULL UNIQUE,
    agent_role  text NOT NULL CHECK (agent_role IN ('client','server')),
    agent_name  text NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.agents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES app.organizations(id),
    name            text NOT NULL,
    role            text NOT NULL CHECK (role IN ('client','server')),
    credential_hash text NOT NULL UNIQUE,      -- sha256 of the agent credential
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    revoked_at      timestamptz
);

CREATE TABLE app.targets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    host        text NOT NULL,
    port        integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    sni         text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.target_agents (
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    target_id   uuid NOT NULL REFERENCES app.targets(id),
    agent_id    uuid NOT NULL REFERENCES app.agents(id),
    PRIMARY KEY (target_id, agent_id)
);

CREATE TABLE app.scan_jobs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    target_id   uuid NOT NULL REFERENCES app.targets(id),
    agent_id    uuid NOT NULL REFERENCES app.agents(id),
    kind        text NOT NULL CHECK (kind IN ('client','server')),
    status      text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','done','failed','not_runnable')),
    error       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz
);
CREATE INDEX scan_jobs_queue ON app.scan_jobs (agent_id, created_at) WHERE status = 'queued';

CREATE TABLE app.scan_results (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    job_id      uuid NOT NULL UNIQUE REFERENCES app.scan_jobs(id),
    target_id   uuid NOT NULL REFERENCES app.targets(id),
    overall     text,
    document    jsonb NOT NULL,                -- findings-contract document
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_results_history ON app.scan_results (target_id, created_at);

-- Results are an immutable history.
CREATE FUNCTION app.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER scan_results_immutable BEFORE UPDATE OR DELETE ON app.scan_results
    FOR EACH ROW EXECUTE FUNCTION app.reject_change();

-- Row-level security: every tenant table is filtered by app.current_org().
ALTER TABLE app.organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON app.organizations USING (id = app.current_org());
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['api_tokens','enrollment_tokens','agents','targets',
                             'target_agents','scan_jobs','scan_results'] LOOP
        EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant ON app.%I USING (org_id = app.current_org()) '
                       'WITH CHECK (org_id = app.current_org())', t);
    END LOOP;
END $$;

GRANT SELECT ON app.organizations TO ssldoctor_app;
GRANT SELECT, INSERT, UPDATE ON app.api_tokens, app.enrollment_tokens, app.agents,
    app.targets, app.scan_jobs TO ssldoctor_app;
GRANT SELECT, INSERT, DELETE ON app.target_agents TO ssldoctor_app;
GRANT SELECT, INSERT ON app.scan_results TO ssldoctor_app;

-- Pre-authentication lookups. SECURITY DEFINER runs as the table owner, which
-- RLS does not filter; each function returns only the caller's own identity.
CREATE FUNCTION app.auth_api_token(p_hash text)
RETURNS TABLE (token_id uuid, org_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT id, api_tokens.org_id, api_tokens.role FROM app.api_tokens
    WHERE token_hash = p_hash AND revoked_at IS NULL
$$;

CREATE FUNCTION app.auth_agent(p_hash text)
RETURNS TABLE (agent_id uuid, org_id uuid, role text, revoked boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT id, agents.org_id, agents.role, revoked_at IS NOT NULL FROM app.agents
    WHERE credential_hash = p_hash
$$;

-- Atomically consume a single-use enrollment token and register the agent.
CREATE FUNCTION app.enroll_agent(p_token_hash text, p_credential_hash text)
RETURNS TABLE (agent_id uuid, org_id uuid, role text, name text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = app, pg_temp AS $$
DECLARE t app.enrollment_tokens;
BEGIN
    UPDATE app.enrollment_tokens SET used_at = now()
     WHERE token_hash = p_token_hash AND used_at IS NULL AND expires_at > now()
    RETURNING * INTO t;
    IF NOT FOUND THEN
        RETURN;                                -- unknown, used or expired
    END IF;
    RETURN QUERY
        INSERT INTO app.agents (org_id, name, role, credential_hash)
        VALUES (t.org_id, t.agent_name, t.agent_role, p_credential_hash)
        RETURNING agents.id, agents.org_id, agents.role, agents.name;
END $$;

REVOKE ALL ON FUNCTION app.auth_api_token(text), app.auth_agent(text),
    app.enroll_agent(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.auth_api_token(text), app.auth_agent(text),
    app.enroll_agent(text, text), app.current_org() TO ssldoctor_app;

RESET ROLE;
