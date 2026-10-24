-- 0002: scheduled monitoring, alert state (dedup), channels, delivery log.
SET ROLE ssldoctor_owner;

ALTER TABLE app.organizations
    ADD COLUMN min_interval_seconds integer NOT NULL DEFAULT 3600
        CHECK (min_interval_seconds >= 60);

ALTER TABLE app.targets
    ADD COLUMN monitor_interval_seconds integer CHECK (monitor_interval_seconds >= 60),
    ADD COLUMN expiry_threshold_days integer NOT NULL DEFAULT 30
        CHECK (expiry_threshold_days BETWEEN 1 AND 365),
    ADD COLUMN next_scan_at timestamptz;
CREATE INDEX targets_due ON app.targets (next_scan_at) WHERE monitor_interval_seconds IS NOT NULL;

CREATE TABLE app.notification_channels (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    kind        text NOT NULL CHECK (kind IN ('email', 'webhook')),
    address     text NOT NULL,                 -- email address or https URL
    secret      text,                          -- webhook HMAC key
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- One row per (target, condition): an alert is sent when it opens, and
-- re-armed only after the condition clears.
CREATE TABLE app.alert_state (
    org_id          uuid NOT NULL REFERENCES app.organizations(id),
    target_id       uuid NOT NULL REFERENCES app.targets(id),
    condition       text NOT NULL,
    is_open         boolean NOT NULL,
    opened_at       timestamptz,
    closed_at       timestamptz,
    last_result_id  uuid REFERENCES app.scan_results(id),
    PRIMARY KEY (target_id, condition)
);

CREATE TABLE app.alerts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES app.organizations(id),
    target_id   uuid NOT NULL REFERENCES app.targets(id),
    channel_id  uuid NOT NULL REFERENCES app.notification_channels(id),
    condition   text NOT NULL,
    payload     jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
    attempts    integer NOT NULL DEFAULT 0,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz
);
CREATE INDEX alerts_pending ON app.alerts (created_at) WHERE status = 'pending';

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['notification_channels','alert_state','alerts'] LOOP
        EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant ON app.%I USING (org_id = app.current_org()) '
                       'WITH CHECK (org_id = app.current_org())', t);
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON app.notification_channels TO ssldoctor_app;
GRANT SELECT, INSERT, UPDATE ON app.alert_state, app.alerts TO ssldoctor_app;
GRANT UPDATE (monitor_interval_seconds, expiry_threshold_days, next_scan_at)
    ON app.targets TO ssldoctor_app;

-- Scheduler/dispatcher entry points: list WHICH tenants have work, without
-- exposing any tenant data; the work itself then runs tenant-scoped.
CREATE FUNCTION app.orgs_with_due_targets(p_now timestamptz)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT DISTINCT targets.org_id FROM app.targets
    WHERE monitor_interval_seconds IS NOT NULL AND next_scan_at <= p_now
$$;

CREATE FUNCTION app.orgs_with_pending_alerts()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = app, pg_temp AS $$
    SELECT DISTINCT alerts.org_id FROM app.alerts WHERE status = 'pending'
$$;

REVOKE ALL ON FUNCTION app.orgs_with_due_targets(timestamptz),
    app.orgs_with_pending_alerts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.orgs_with_due_targets(timestamptz),
    app.orgs_with_pending_alerts() TO ssldoctor_app;

RESET ROLE;
