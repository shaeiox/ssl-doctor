-- 0003: tamper-evident, append-only audit log (per-organization hash chain).
SET ROLE ssldoctor_owner;

CREATE TABLE app.audit_log (
    id          bigserial PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    seq         bigint NOT NULL,               -- 1, 2, 3 ... per organization
    created_at  timestamptz NOT NULL,
    actor       text NOT NULL,                 -- e.g. member:<id>, agent:<id>, system
    action      text NOT NULL,                 -- e.g. agent.revoke
    object      text,                          -- e.g. agent:<id>
    source_ip   text,
    entry       text NOT NULL,                 -- canonical JSON that was hashed
    prev_hash   text NOT NULL,                 -- 64 zeros for seq 1
    hash        text NOT NULL,                 -- sha256(prev_hash || '\n' || entry)
    UNIQUE (org_id, seq)
);
CREATE INDEX audit_log_time ON app.audit_log (org_id, created_at);

CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON app.audit_log
    FOR EACH ROW EXECUTE FUNCTION app.reject_change();

ALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON app.audit_log USING (org_id = app.current_org())
    WITH CHECK (org_id = app.current_org());

GRANT SELECT, INSERT ON app.audit_log TO ssldoctor_app;
GRANT USAGE ON SEQUENCE app.audit_log_id_seq TO ssldoctor_app;

RESET ROLE;
