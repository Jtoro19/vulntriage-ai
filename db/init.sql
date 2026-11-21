-- Runs once when the Postgres volume is created.
CREATE DATABASE n8n;
CREATE DATABASE vulntriage;
\connect vulntriage
CREATE TABLE IF NOT EXISTS findings (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    pipeline      TEXT NOT NULL,            -- n8n | langchain
    run_id        TEXT NOT NULL,
    asset         TEXT,
    host          TEXT,
    port          INTEGER,
    service       TEXT,
    product       TEXT,
    version       TEXT,
    cve_id        TEXT,
    cvss_score    NUMERIC(3,1),
    epss          NUMERIC(6,5),
    in_kev        BOOLEAN,
    cwes          TEXT,
    attack_technique TEXT,
    critical      BOOLEAN,
    priority      NUMERIC(5,1),
    summary       TEXT,
    llm_provider  TEXT
);
CREATE INDEX IF NOT EXISTS findings_run_idx ON findings (run_id);
