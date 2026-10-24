-- 0004: users, sessions, SSO (OIDC/SAML) configuration, SCIM provisioning.
SET ROLE ssldoctor_owner;

ALTER TABLE app.organizations ADD COLUMN slug text UNIQUE
    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$');

CREATE TABLE app.users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES app.organizations(id),
    email         text NOT NULL,
    display_name  text,
    role          text NOT NULL CHECK (role IN ('owner','admin','engineer','viewer')),
    external_id   text,                         -- IdP subject / SCIM externalId
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    removed_at    timestamptz
);
CREATE UNIQUE INDEX users_email ON app.users (org_id, lower(email));
CREATE UNIQUE INDEX users_external ON app.users (org_id, external_id) WHERE external_id IS NOT NULL;

-- Tokens belong to a user; the user's CURRENT role and state apply.
ALTER TABLE app.api_tokens ADD COLUMN user_id uuid REFERENCES app.users(id);

CREATE TABLE app.sessions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    user_id     uuid NOT NULL REFERENCES app.users(id),
    token_hash  text NOT NULL UNIQUE,
    method      text NOT NULL CHECK (method IN ('api-token','oidc','saml')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE TABLE app.sso_configs (
    org_id              uuid PRIMARY KEY REFERENCES app.organizations(id),
    protocol            text NOT NULL CHECK (protocol IN ('oidc','saml')),
    enforced            boolean NOT NULL DEFAULT false,
    default_role        text NOT NULL DEFAULT 'viewer'
                        CHECK (default_role IN ('admin','engineer','viewer')),
    jit_provisioning    boolean NOT NULL DEFAULT false,
    oidc_issuer         text,
    oidc_client_id      text,
    oidc_client_secret  text,
    oidc_authorize_url  text,
    oidc_token_url      text,
    oidc_jwks_url       text,
    saml_idp_entity_id  text,
    saml_idp_sso_url    text,
    saml_idp_cert       text,
    scim_token_hash     text UNIQUE,
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.sso_states (
    state_hash     text PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES app.organizations(id),
    nonce          text NOT NULL,
    code_verifier  text,
    expires_at     timestamptz NOT NULL
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['users','sessions','sso_configs','sso_states'] LOOP
        EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant ON app.%I USING (org_id = app.current_org()) '
                       'WITH CHECK (org_id = app.current_org())', t);
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE ON app.users, app.sessions, app.sso_configs TO ssldoctor_app;
GRANT SELECT, INSERT, DELETE ON app.sso_states TO ssldoctor_app;
GRANT UPDATE (revoked_at) ON app.api_tokens TO ssldoctor_app;

-- Bring existing (pre-0004) tokens under users: one user per legacy token.
INSERT INTO app.users (id, org_id, email, role)
    SELECT t.id, t.org_id, 'legacy-token-' || t.id || '@localhost', t.role FROM app.api_tokens t;
UPDATE app.api_tokens SET user_id = id WHERE user_id IS NULL;
ALTER TABLE app.api_tokens ALTER COLUMN user_id SET NOT NULL;

-- Token auth now honours the user's current role and active state.
DROP FUNCTION app.auth_api_token(text);
CREATE FUNCTION app.auth_api_token(p_hash text)
RETURNS TABLE (token_id uuid, org_id uuid, role text, user_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT t.id, t.org_id, u.role, u.id FROM app.api_tokens t
    JOIN app.users u ON u.id = t.user_id
    WHERE t.token_hash = p_hash AND t.revoked_at IS NULL AND u.active
$$;

CREATE FUNCTION app.auth_session(p_hash text)
RETURNS TABLE (session_id uuid, org_id uuid, role text, user_id uuid, method text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT s.id, s.org_id, u.role, u.id, s.method FROM app.sessions s
    JOIN app.users u ON u.id = s.user_id
    WHERE s.token_hash = p_hash AND s.revoked_at IS NULL AND s.expires_at > now() AND u.active
$$;

-- Pre-authentication: which org a sign-in or SCIM request belongs to.
CREATE FUNCTION app.org_login_info(p_slug text)
RETURNS TABLE (org_id uuid, protocol text, enforced boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT o.id, c.protocol, coalesce(c.enforced, false) FROM app.organizations o
    LEFT JOIN app.sso_configs c ON c.org_id = o.id WHERE o.slug = p_slug
$$;

CREATE FUNCTION app.sso_enforced(p_org uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT coalesce((SELECT enforced FROM app.sso_configs WHERE org_id = p_org), false)
$$;

CREATE FUNCTION app.auth_scim(p_hash text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT org_id FROM app.sso_configs WHERE scim_token_hash = p_hash
$$;

REVOKE ALL ON FUNCTION app.auth_session(text), app.org_login_info(text),
    app.sso_enforced(uuid), app.auth_scim(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.auth_api_token(text), app.auth_session(text),
    app.org_login_info(text), app.sso_enforced(uuid), app.auth_scim(text) TO ssldoctor_app;

RESET ROLE;
