-- ARTEX PostgreSQL schema (单一数据源)
-- 幂等：可重复执行（IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS）。

-- =====================================================================
-- 0. 通用：updated_at 触发器
-- =====================================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- 安全的 text→inet 转换：非法值返回 NULL 而不是抛 22P02。assets.ip 是自由文本
-- (Agent / 资产 API 可能写进主机名)，裸转 a.ip::inet 会让单独一行脏数据把整条
-- 企业归属重算语句打挂。调用方用 try_inet(...) IS NULL 找出这些行并告警。
-- 不用 pg_input_is_valid 是因为那要 PG16+，这里要兼容更老的存量库。
CREATE OR REPLACE FUNCTION try_inet(value text) RETURNS inet AS $$
BEGIN
    RETURN value::inet;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- =====================================================================
-- A. 资产层：companies / assets / company_scope
-- =====================================================================

CREATE TABLE IF NOT EXISTS companies (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    logo       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_companies_nkey ON companies(nkey);
DROP TRIGGER IF EXISTS trg_companies_upd ON companies;
CREATE TRIGGER trg_companies_upd BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS assets (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL CHECK (type IN (
                        'root_domain','ip','subdomain','app','service','endpoint'
                    )),
    company_id      BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    -- explicit: caller/user selected the company; scope: derived from company_scope.
    -- Existing installations are conservatively migrated as explicit so a scope
    -- rebuild can never erase a historical manual association.
    company_source  TEXT NOT NULL DEFAULT 'explicit'
                    CHECK (company_source IN ('explicit','scope')),
    task_ids        BIGINT[] NOT NULL DEFAULT '{}',
    domain          TEXT,
    root_domain     TEXT,
    ip              TEXT,
    c_segment       CIDR,
    port            INTEGER CHECK (port BETWEEN 1 AND 65535),
    icp             TEXT,
    bound_domains   TEXT[]  NOT NULL DEFAULT '{}',
    open_ports      JSONB[] NOT NULL DEFAULT '{}',
    record_type     TEXT,
    record_value    TEXT[],
    bundle_id       TEXT,
    app_name        TEXT,
    category        TEXT,
    app_description TEXT,
    app_icp         TEXT,
    url             TEXT,
    service_type    TEXT CHECK (service_type IN ('http','other')),
    service_name    TEXT,
    favicon_mmh3    TEXT,
    status_code     INTEGER,
    content_length  BIGINT,
    page_title      TEXT,
    technologies    TEXT[]  NOT NULL DEFAULT '{}',
    auth            JSONB[] NOT NULL DEFAULT '{}',
    method          TEXT,
    params          JSONB[] NOT NULL DEFAULT '{}',
    extra           JSONB   NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_root_domain  ON assets(domain) WHERE type = 'root_domain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_ip           ON assets(ip)     WHERE type = 'ip';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_subdomain    ON assets(domain, COALESCE(record_type,'')) WHERE type = 'subdomain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_bundle   ON assets(bundle_id) WHERE type = 'app' AND bundle_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_name     ON assets(app_name)  WHERE type = 'app' AND bundle_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_http ON assets(url) WHERE type = 'service' AND service_type = 'http';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_other
    ON assets(COALESCE(domain,''), COALESCE(ip,''), port, service_name) WHERE type = 'service' AND service_type = 'other';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_endpoint     ON assets(url, method) WHERE type = 'endpoint';
CREATE INDEX IF NOT EXISTS idx_av2_company      ON assets(company_id)       WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_company_type ON assets(company_id, type) WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_task_ids     ON assets USING GIN(task_ids);
CREATE INDEX IF NOT EXISTS idx_av2_domain       ON assets(domain)      WHERE domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_root_domain  ON assets(root_domain) WHERE root_domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_ip           ON assets(ip)          WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_c_segment    ON assets USING GIST(c_segment inet_ops) WHERE c_segment IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_technologies ON assets USING GIN(technologies) WHERE type = 'service';
CREATE INDEX IF NOT EXISTS idx_av2_bound_domains ON assets USING GIN(bound_domains) WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_open_ports   ON assets USING GIN(open_ports)    WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_last_seen    ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_av2_type_seen    ON assets(type, last_seen DESC);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS company_source TEXT;
UPDATE assets SET company_source = 'explicit' WHERE company_source IS NULL;
ALTER TABLE assets ALTER COLUMN company_source SET DEFAULT 'explicit';
ALTER TABLE assets ALTER COLUMN company_source SET NOT NULL;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_company_source_check;
ALTER TABLE assets ADD CONSTRAINT assets_company_source_check
    CHECK (company_source IN ('explicit','scope'));
DROP TRIGGER IF EXISTS trg_av2_upd ON assets;
CREATE TRIGGER trg_av2_upd BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS company_scope (
    id         BIGSERIAL PRIMARY KEY,
    company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('domain','ip','cidr','icp','keyword')),
    domain     TEXT,
    net        CIDR,
    value      TEXT,
    raw        TEXT NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_sv2_domain UNIQUE (company_id, domain),
    CONSTRAINT uq_sv2_net    UNIQUE (company_id, net),
    CONSTRAINT ck_company_scope_payload CHECK (
        (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
        OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
        OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
    )
);
-- Existing installations need the new text payload and expanded kind check.
ALTER TABLE company_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS company_scope_kind_check;
ALTER TABLE company_scope ADD CONSTRAINT company_scope_kind_check
    CHECK (kind IN ('domain','ip','cidr','icp','keyword'));
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS ck_company_scope_payload;
ALTER TABLE company_scope ADD CONSTRAINT ck_company_scope_payload CHECK (
    (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
    OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
    OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_sv2_domain  ON company_scope(domain)   WHERE kind = 'domain';
CREATE INDEX IF NOT EXISTS idx_sv2_net     ON company_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE UNIQUE INDEX IF NOT EXISTS uq_sv2_value ON company_scope(company_id, kind, value) WHERE kind IN ('icp','keyword');
CREATE INDEX IF NOT EXISTS idx_sv2_icp ON company_scope(value) WHERE kind = 'icp';
CREATE INDEX IF NOT EXISTS idx_sv2_company ON company_scope(company_id);

-- =====================================================================
-- B. 推理探索层
-- =====================================================================
CREATE TABLE IF NOT EXISTS explorations (
    id          BIGSERIAL PRIMARY KEY,
    description TEXT,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','achieved','failed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- cold-digest (§2.3): per-task planner round counter — bumped once each time the
-- planner wakes and processes a round. Drives the ≥R cold-node debounce (measured in
-- this exploration's own rounds, not global node ids or wall-clock).
ALTER TABLE explorations ADD COLUMN IF NOT EXISTS round_no BIGINT NOT NULL DEFAULT 0;
DROP TRIGGER IF EXISTS trg_exp_upd ON explorations;
CREATE TRIGGER trg_exp_upd BEFORE UPDATE ON explorations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_nodes (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}',
    priority       INT  NOT NULL DEFAULT 0,
    state          TEXT NOT NULL DEFAULT 'open',
    origin         TEXT,
    owner          TEXT,
    blocked_reason TEXT,
    delete_reason  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    CONSTRAINT ck_node_kind CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest')),
    CONSTRAINT ck_node_state CHECK (
        (kind='begin'   AND state IN ('open')) OR
        (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
        (kind='goal'    AND state IN ('open','met','abandoned')) OR
        (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
        (kind='finding' AND state IN ('confirmed','dismissed')) OR
        (kind='hint'    AND state IN ('active','consumed')) OR
        (kind='digest'  AND state IN ('active','superseded'))
    )
);
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
-- 意图假删除(soft delete):state='deleted' 时,delete_reason 记用户填写的删除原因。
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS delete_reason TEXT;
-- cold-digest (§2.3/§5.3): content_version bumps on any change that could alter a
-- digest body (summary/state/confidence); cold_since_round stamps the planner round
-- a node most recently went from "has a live downstream branch" to none (NULL = hot).
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS content_version  INT    NOT NULL DEFAULT 0;
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS cold_since_round BIGINT;
-- ck_node_kind: existing installs predate the 'digest' kind — recreate to allow it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_kind'
          AND pg_get_constraintdef(oid) NOT LIKE '%digest%'
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_kind;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_kind
            CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest'));
    END IF;
END $$;
-- ck_node_state: recreate when it lacks the 'paused' (older), 'superseded' (digest rev),
-- or 'deleted' (intent soft-delete rev) branches.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_state'
          AND (pg_get_constraintdef(oid) NOT LIKE '%paused%'
               OR pg_get_constraintdef(oid) NOT LIKE '%superseded%'
               OR pg_get_constraintdef(oid) NOT LIKE '%deleted%')
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_state;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_state CHECK (
            (kind='begin'   AND state IN ('open')) OR
            (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
            (kind='goal'    AND state IN ('open','met','abandoned')) OR
            (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
            (kind='finding' AND state IN ('confirmed','dismissed')) OR
            (kind='hint'    AND state IN ('active','consumed')) OR
            (kind='digest'  AND state IN ('active','superseded'))
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_expnodes_part     ON exploration_nodes(exploration_id, kind);
CREATE INDEX IF NOT EXISTS idx_expnodes_frontier ON exploration_nodes(exploration_id, priority DESC)
    WHERE kind='intent' AND state='open';
DROP TRIGGER IF EXISTS trg_expnodes_upd ON exploration_nodes;
CREATE TRIGGER trg_expnodes_upd BEFORE UPDATE ON exploration_nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_edges (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    src_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    dst_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    rel            TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, src_id, rel, dst_id),
    CONSTRAINT ck_edge_noself CHECK (src_id <> dst_id),
    CONSTRAINT ck_edge_rel CHECK (rel IN ('spawns','derived_from','yields','proves','covers'))
);
CREATE INDEX IF NOT EXISTS idx_expedges_src ON exploration_edges(src_id, rel);
CREATE INDEX IF NOT EXISTS idx_expedges_dst ON exploration_edges(dst_id, rel);
-- cold-digest (§1): the 'covers' relation (digest→member) postdates shipped installs,
-- whose rel CHECK is an inline auto-named constraint. Find and recreate it as ck_edge_rel.
DO $$
DECLARE cname text;
BEGIN
    SELECT conname INTO cname FROM pg_constraint
     WHERE conrelid='exploration_edges'::regclass AND contype='c'
       AND pg_get_constraintdef(oid) LIKE '%rel%'
       AND pg_get_constraintdef(oid) NOT LIKE '%covers%';
    IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE exploration_edges DROP CONSTRAINT '||quote_ident(cname);
        ALTER TABLE exploration_edges ADD CONSTRAINT ck_edge_rel
            CHECK (rel IN ('spawns','derived_from','yields','proves','covers'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS exploration_anchors (
    node_id   BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    asset_id  BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_anchor_asset ON exploration_anchors(asset_id);

-- task_constraints: operator-authored operation constraints (allow/deny) for a task.
-- Extracted by the goals decomposer at round 0 (from goal/description), editable at
-- runtime by the main agent + 总览「约束管理」. Injected into the planner/worker system
-- prompt each round (config-gated) to keep exploration within the operator's boundary.
CREATE TABLE IF NOT EXISTS task_constraints (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('allow','deny')),
    text           TEXT NOT NULL,
    origin         TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_constraints_exp ON task_constraints(exploration_id);

CREATE TABLE IF NOT EXISTS activity (
    id                 BIGSERIAL PRIMARY KEY,
    exploration_id     BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    node_id            BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}',
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE activity ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
-- main_seg segments the main-agent session into resettable conversations: a new
-- main session bumps the segment so its transcript + activity start clean while the
-- task's graph/assets/goal are untouched. NULL == legacy rows == segment 0 (the
-- original session). Only worker='mainagent' rows carry it.
ALTER TABLE activity ADD COLUMN IF NOT EXISTS main_seg INTEGER;
CREATE INDEX IF NOT EXISTS idx_act_node  ON activity(exploration_id, node_id, id);
CREATE INDEX IF NOT EXISTS idx_act_since ON activity(exploration_id, id);
CREATE INDEX IF NOT EXISTS idx_act_tool_call ON activity(exploration_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');
-- Main/Plan history pages filter by worker (both carry NULL node_id, so idx_act_node
-- can't distinguish them); this covers reverse pagination of those sessions.
CREATE INDEX IF NOT EXISTS idx_act_worker ON activity(exploration_id, worker, id);
-- Main-session pages filter by segment on top of worker='mainagent'; this partial
-- index covers reverse pagination within one segment.
CREATE INDEX IF NOT EXISTS idx_act_main_seg ON activity(exploration_id, main_seg, id)
    WHERE worker='mainagent';
-- Task-list polls aggregate result usage and find the latest event repeatedly.
-- Cover the token columns for index-only aggregation and the timestamp order for
-- per-exploration latest-activity lookups.
CREATE INDEX IF NOT EXISTS idx_act_result_usage ON activity(exploration_id)
    INCLUDE (input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
    WHERE kind='result';
CREATE INDEX IF NOT EXISTS idx_act_latest ON activity(exploration_id, created_at DESC);

-- main_sessions records the resettable main-agent conversation segments of a task.
-- Segment 0 (the original session) is implicit and never stored; this table holds
-- only the extra segments created by "新建会话" (seq >= 1). The current segment is
-- MAX(seq) or 0. Each segment gets its own transcript file + activity slice; the
-- task's exploration graph/assets/goal are shared and never reset.
CREATE TABLE IF NOT EXISTS main_sessions (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, seq)
);

-- =====================================================================
-- C. LLM profiles
-- =====================================================================
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    format           TEXT NOT NULL CHECK (format IN ('openai','anthropic','openai-responses')),
    base_url         TEXT,
    proxy            TEXT,
    model            TEXT NOT NULL,
    api_key          TEXT,
    api_key_hint     TEXT,
    rate_per_second  DOUBLE PRECISION NOT NULL DEFAULT 0,
    rate_per_minute  DOUBLE PRECISION NOT NULL DEFAULT 0,
    context_window_k INTEGER NOT NULL DEFAULT 0,
    -- 思考参数拆成两个独立字段：thinking_type=思考开关(''/disabled/enabled)，
    -- reasoning_effort=思考强度(''/low/medium/high/xhigh/max)，互不牵连。
    reasoning_effort TEXT NOT NULL DEFAULT '',
    thinking_type    TEXT NOT NULL DEFAULT '',
    is_default       BOOLEAN NOT NULL DEFAULT false,
    -- 轮询(故障转移)参数，见 docs/LLM轮询设计.md：
    --   priority     顺位，越大越先被选中；激活配置(is_default)永远排链首，与本值无关。
    --   pool_exclude true=不作为故障转移目标(仍可被 agent/任务显式绑定使用)。
    priority         INTEGER NOT NULL DEFAULT 0,
    pool_exclude     BOOLEAN NOT NULL DEFAULT false,
    -- streaming=true(默认)走流式 SSE；false 走真·非流式(stream:false，一次性 JSON)。
    streaming        BOOLEAN NOT NULL DEFAULT true,
    -- 单次回复的输出上限(token)。0=不发送该字段，由服务端默认值决定——保持既有行为。
    -- 与 context_window_k(模型总容量，仅本地用于压缩阈值)是两回事：本值会随请求发出。
    max_tokens       INTEGER NOT NULL DEFAULT 0,
    -- 输出上限用哪个请求字段名，仅对 format='openai' 生效：
    --   ''                      = max_tokens(默认，兼容绝大多数网关)
    --   'max_completion_tokens' = 新字段；OpenAI 推理模型(o 系列/GPT-5)只认它，
    --                             发 max_tokens 会被 unsupported_parameter 拒绝。
    -- anthropic(max_tokens 必填)与 openai-responses(max_output_tokens)自带字段名，不受此值影响。
    max_tokens_field TEXT NOT NULL DEFAULT '',
    -- 自定义会话头：非空时每次请求带一个该名字的 HTTP 头，头值=当前运行的 session id
    -- (chat 会话/worker 意图)。用于某些按 session-id 头做提示缓存/粘性路由的网关。''=不发送。
    session_header_key TEXT NOT NULL DEFAULT '',
    -- 重试覆盖：次数 0=用全局默认/-1=关闭/>0=该值；间隔 0=用默认指数退避/>0=固定毫秒。
    -- 三组分别对应建连重试、空响应重试、同 provider 安全窗口重试，详见下方 ALTER 处注释。
    retry_connect_attempts    INTEGER NOT NULL DEFAULT 0,
    retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0,
    retry_empty_attempts      INTEGER NOT NULL DEFAULT 0,
    retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0,
    retry_stream_attempts     INTEGER NOT NULL DEFAULT 0,
    retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_one_default ON llm_profiles(is_default) WHERE is_default;
DROP TRIGGER IF EXISTS trg_llm_upd ON llm_profiles;
CREATE TRIGGER trg_llm_upd BEFORE UPDATE ON llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- 轮询顺位/排除标记；补旧库。默认 0 / false = 全部配置都参与轮询。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS priority     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS pool_exclude BOOLEAN NOT NULL DEFAULT false;
-- 流式开关；补旧库。默认 true = 保持既有的流式行为，旧配置无感升级。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS streaming    BOOLEAN NOT NULL DEFAULT true;
-- 放开 format 约束以容纳 openai-responses(OpenAI Responses API)；补旧库。
-- 每次启动执行,幂等:先删旧 CHECK 再建含三值的新 CHECK。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_format_check
    CHECK (format IN ('openai','anthropic','openai-responses'));

-- 输出上限及其字段名；补旧库。默认 0 / '' = 不发送上限、沿用 max_tokens 字段名，
-- 旧配置行为完全不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens_field TEXT    NOT NULL DEFAULT '';
-- 同 format：先删再建，保证每次启动幂等。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_field_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_field_check
    CHECK (max_tokens_field IN ('','max_completion_tokens'));
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_check
    CHECK (max_tokens >= 0);
-- 自定义会话头名；补旧库。默认 '' = 不发送，旧配置行为不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS session_header_key TEXT NOT NULL DEFAULT '';

-- 单配置的重试覆盖（见 docs/LLM重试设计.md）。三组各自一对「次数 + 固定间隔」，
-- 语义统一：次数 0=沿用全局默认、-1=关闭该层重试、>0=用该值；间隔 0=沿用该层的
-- 默认指数退避、>0=改用这个固定毫秒数。全部默认 0，所以旧库/旧配置行为不变。
--   connect = 建连重试（SDK doStream：连接重置/超时/429/5xx，流开始前）
--   empty   = 空响应重试（SDK：完成但没有任何 content block，仅 openai 格式）
--   stream  = 同 provider 安全窗口重试（本项目 task_llm：未交付输出前的断流重放）
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_attempts    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_attempts      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_attempts     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0;
-- 同 format：先删再建，保证每次启动幂等。次数下限 -1(关闭)，间隔不能为负。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_retry_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_retry_check CHECK (
    retry_connect_attempts >= -1 AND retry_empty_attempts >= -1 AND retry_stream_attempts >= -1
    AND retry_connect_interval_ms >= 0 AND retry_empty_interval_ms >= 0 AND retry_stream_interval_ms >= 0);

-- 思考开关字段 thinking_type，从旧的单一 reasoning_effort 语义一次性拆分而来。
-- schema.sql 每次启动都执行，故迁移必须只跑一次：仅当该列尚不存在时才回填，
-- 否则每次启动都会把用户后来手动设的组合覆盖回去。旧 reasoning_effort 语义：
--   'off'                    → 显式关闭  → thinking_type='disabled'，强度清空
--   'low/medium/high/max'    → 开启+强度 → thinking_type='enabled'，强度保留
--   ''                       → 不发送    → 两者皆空(默认)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'llm_profiles' AND column_name = 'thinking_type'
    ) THEN
        ALTER TABLE llm_profiles ADD COLUMN thinking_type TEXT NOT NULL DEFAULT '';
        UPDATE llm_profiles SET thinking_type = 'enabled'
            WHERE reasoning_effort IN ('low','medium','high','max');
        UPDATE llm_profiles SET thinking_type = 'disabled', reasoning_effort = ''
            WHERE reasoning_effort = 'off';
    END IF;
END $$;

-- LLM 轮询熔断状态：某个配置连续失败(余额不足/key 失效/限流)后进入冷却，冷却期内
-- 轮询直接跳过它。内存态为准，这里落库只为重启后不丢冷却窗口——加载时只取尚未
-- 到期的行(open_until > now)，已到期的自然回到"正常"，等下一次调用半开试探。
CREATE TABLE IF NOT EXISTS llm_profile_health (
    profile_id  BIGINT PRIMARY KEY REFERENCES llm_profiles(id) ON DELETE CASCADE,
    fails       INTEGER NOT NULL DEFAULT 0,  -- 当前连续失败次数(成功即清零)
    trips       INTEGER NOT NULL DEFAULT 0,  -- 累计熔断次数,用于冷却时间指数退避
    open_until  TIMESTAMPTZ,                 -- 冷却截止;NULL/过期 = 未熔断
    last_error  TEXT NOT NULL DEFAULT '',
    last_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
-- D. 任务层
-- =====================================================================
-- Global task categories are intentionally independent from task templates.
-- Deleting a category only moves its tasks back to the uncategorized bucket.
CREATE TABLE IF NOT EXISTS task_categories (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_categories_name ON task_categories(name, id);
DROP TRIGGER IF EXISTS trg_task_categories_upd ON task_categories;
CREATE TRIGGER trg_task_categories_upd BEFORE UPDATE ON task_categories
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS tasks (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    category_id    BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    description    TEXT NOT NULL,
    goal           TEXT NOT NULL,
    exploration_id BIGINT NOT NULL UNIQUE
                     REFERENCES explorations(id) ON DELETE RESTRICT,
    status         TEXT NOT NULL DEFAULT 'created'
                     CHECK (status IN ('created','running','paused','done','failed','timeout')),
    paused         BOOLEAN NOT NULL DEFAULT false,
    queued         BOOLEAN NOT NULL DEFAULT false,
    queued_at      TIMESTAMPTZ,
    queue_mode     TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    llm_chain_revision BIGINT NOT NULL DEFAULT 0,
    company_id     BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    parent_ref     TEXT,
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300,
    coverage_enabled BOOLEAN NOT NULL DEFAULT true,
    pinned_at      TIMESTAMPTZ,
    first_run_at   TIMESTAMPTZ,
    deadline_at    TIMESTAMPTZ,
    archived_at    TIMESTAMPTZ,
    deleted_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_alive  ON tasks(created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)          WHERE deleted_at IS NULL;
DROP TRIGGER IF EXISTS trg_tasks_upd ON tasks;
CREATE TRIGGER trg_tasks_upd BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- planner 心跳触发间隔(秒);补旧库。默认 300s(5min)。见 docs/planner-trigger-impl-plan.md
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300;
-- 并发上限挂起态;补旧库。true=因并发上限排队、等待空位自动启动。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued BOOLEAN NOT NULL DEFAULT false;
-- 资产覆盖度功能开关;补旧库。true(默认)=计算/展示测试覆盖度、自动累积测试范围、
-- 给 agent 开放 add_task_scope/list_untested_assets;false=全部关闭(见 task_scope.go)。
-- 存量任务默认 true 保持原行为;company 关联(task_scope kind=company)不受此开关影响。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS coverage_enabled BOOLEAN NOT NULL DEFAULT true;
-- queued_at makes admission FIFO reflect the actual enqueue order rather than the
-- task creation order. queue_mode distinguishes first bootstrap from resuming an
-- exploration that already owns goals/history.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queue_mode TEXT NOT NULL DEFAULT '';
-- 可选的任务名称;补旧库。空串=未命名,前端展示时回退到描述。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS llm_chain_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category_id, created_at DESC)
    WHERE deleted_at IS NULL AND category_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_pinned ON tasks(pinned_at DESC)
    WHERE deleted_at IS NULL AND pinned_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_archived ON tasks(archived_at DESC)
    WHERE archived_at IS NOT NULL;

-- Cold task archives retain only compact metadata in PostgreSQL. The complete
-- task payload lives in a versioned .tar.zst package under data/archives/tasks.
-- task_id stays unique so an operation can be retried safely after a restart.
CREATE TABLE IF NOT EXISTS task_archives (
    id                         BIGSERIAL PRIMARY KEY,
    task_id                    BIGINT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
    state                      TEXT NOT NULL DEFAULT 'archive_queued' CHECK (state IN (
                                   'archive_queued','archiving','archive_failed','ready',
                                   'restore_queued','restoring','restore_failed',
                                   'delete_queued','deleting','delete_failed'
                               )),
    phase                      TEXT NOT NULL DEFAULT 'queued',
    progress                   INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    error                      TEXT NOT NULL DEFAULT '',
    warnings                   JSONB NOT NULL DEFAULT '[]',
    format_version             INTEGER NOT NULL DEFAULT 2,
    archive_path               TEXT NOT NULL DEFAULT '',
    sha256                     TEXT NOT NULL DEFAULT '',
    original_size              BIGINT NOT NULL DEFAULT 0,
    compressed_size            BIGINT NOT NULL DEFAULT 0,
    task_name                  TEXT NOT NULL DEFAULT '',
    task_description           TEXT NOT NULL DEFAULT '',
    task_goal                  TEXT NOT NULL DEFAULT '',
    original_status            TEXT NOT NULL DEFAULT '',
    category_id_snapshot       BIGINT,
    category_name_snapshot     TEXT NOT NULL DEFAULT '',
    source_task_ids            BIGINT[] NOT NULL DEFAULT '{}',
    remaining_timeout_seconds  BIGINT NOT NULL DEFAULT 0,
    data_counts                JSONB NOT NULL DEFAULT '{}',
    aggregate_stats            JSONB NOT NULL DEFAULT '{}',
    archived_at                TIMESTAMPTZ,
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE task_archives ALTER COLUMN format_version SET DEFAULT 2;
CREATE INDEX IF NOT EXISTS idx_task_archives_state ON task_archives(state, requested_at, id);
CREATE INDEX IF NOT EXISTS idx_task_archives_archived ON task_archives(archived_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_task_archives_sources ON task_archives USING GIN(source_task_ids);
DROP TRIGGER IF EXISTS trg_task_archives_upd ON task_archives;
CREATE TRIGGER trg_task_archives_upd BEFORE UPDATE ON task_archives
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reusable task description/goal presets. nkey is the normalized, case-insensitive
-- identity used to reject visually equivalent duplicate names.
CREATE TABLE IF NOT EXISTS task_templates (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    nkey        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    goal        TEXT NOT NULL,
    -- 预设的任务分类；分类删除时置空（与 tasks.category_id 一致，不阻断）。
    category_id     BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    -- 预设的任务级拦截/允许规则快照(AssetInterceptRuleInput 数组)；应用模板时灌进新任务。
    intercept_rules JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 补旧库(已发版,加列带 IF NOT EXISTS)。
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS intercept_rules JSONB NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_task_templates_updated ON task_templates(updated_at DESC, id DESC);
DROP TRIGGER IF EXISTS trg_task_templates_upd ON task_templates;
CREATE TRIGGER trg_task_templates_upd BEFORE UPDATE ON task_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Direct, read-only task context inheritance. Relations are intentionally not
-- recursive: a task sees only the source tasks explicitly chosen at creation.
CREATE TABLE IF NOT EXISTS task_relations (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    source_task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, source_task_id),
    CONSTRAINT ck_task_relation_not_self CHECK (task_id <> source_task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_relations_source ON task_relations(source_task_id);

-- Task/asset provenance supplements the legacy assets.task_ids association. The
-- array remains the compatibility source for existing query and cleanup paths;
-- this relation records how each association was obtained for operator review.
CREATE TABLE IF NOT EXISTS task_asset_links (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    asset_id       BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source         TEXT NOT NULL DEFAULT 'system',
    source_summary TEXT NOT NULL DEFAULT '',
    source_node_id BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_asset ON task_asset_links(asset_id, task_id);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_node ON task_asset_links(source_node_id)
    WHERE source_node_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_asset_links_upd ON task_asset_links;
CREATE TRIGGER trg_task_asset_links_upd BEFORE UPDATE ON task_asset_links
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Keep provenance rows synchronized when existing asset upsert paths append or
-- remove task ids. Detailed callers overwrite the generic source after upsert.
CREATE OR REPLACE FUNCTION sync_task_asset_links() RETURNS trigger AS $$
BEGIN
    INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
    SELECT task.id, NEW.id, 'system', '任务执行期间自动关联'
    FROM unnest(NEW.task_ids) AS requested(task_id)
    JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
    ON CONFLICT (task_id, asset_id) DO NOTHING;

    DELETE FROM task_asset_links link
    WHERE link.asset_id=NEW.id
      AND NOT (link.task_id=ANY(NEW.task_ids));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_assets_task_links ON assets;
CREATE TRIGGER trg_assets_task_links AFTER INSERT OR UPDATE OF task_ids ON assets
    FOR EACH ROW EXECUTE FUNCTION sync_task_asset_links();

-- Existing installations receive an auditable legacy source without rewriting
-- task_ids. Ignore stale array ids that no longer resolve to a live task.
INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
SELECT task.id, asset.id, 'legacy', '由历史任务资产关联迁移'
FROM assets asset
CROSS JOIN LATERAL unnest(asset.task_ids) AS requested(task_id)
JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
ON CONFLICT (task_id, asset_id) DO NOTHING;

-- Ordered task-level LLM failover chain. A quota-exhausted entry is skipped
-- until the user saves/resets the chain, which clears all failure state.
CREATE TABLE IF NOT EXISTS task_llm_profiles (
    task_id          BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    profile_id       BIGINT NOT NULL REFERENCES llm_profiles(id) ON DELETE CASCADE,
    position         INTEGER NOT NULL CHECK (position >= 0),
    status           TEXT NOT NULL DEFAULT 'ready'
                       CHECK (status IN ('ready','quota_exhausted')),
    last_error       TEXT,
    exhausted_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, profile_id),
    UNIQUE (task_id, position)
);
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_order ON task_llm_profiles(task_id, position);
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_profile ON task_llm_profiles(profile_id, task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_llm_profile ON tasks(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_active_llm_profile ON tasks(active_llm_profile_id) WHERE active_llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_llm_profiles_upd ON task_llm_profiles;
CREATE TRIGGER trg_task_llm_profiles_upd BEFORE UPDATE ON task_llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One-time-compatible backfill: old pinned tasks become one-entry chains. A user
-- can still clear the chain later because the update path also clears the legacy
-- llm_profile_id column, preventing this block from re-adding it on restart.
INSERT INTO task_llm_profiles(task_id, profile_id, position)
SELECT t.id, t.llm_profile_id, 0
FROM tasks t
WHERE t.llm_profile_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id)
ON CONFLICT DO NOTHING;
UPDATE tasks t
SET active_llm_profile_id = t.llm_profile_id
WHERE t.active_llm_profile_id IS NULL
  AND t.llm_profile_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id AND x.profile_id=t.llm_profile_id);

-- 任务测试范围（资产覆盖度的分母 + 授权边界）。
--   自动填(source='auto')：insertAssets 顶层按 worker 显式插入的资产类型加保守范围
--     （root_domain→root_domain，subdomain/service/endpoint→subdomain(host)，ip→ip）；
--     side-effect 派生的资产不入范围（钩子在 handler 顶层，派生在 db 层内部）。
--   agent 填(source='agent')：add_task_scope 加 company/root_domain/subdomain/ip。
-- 覆盖度 = 匹配 active 行的 assets（分母）中，被 fact 节点锚定过的占比（分子）。
CREATE TABLE IF NOT EXISTS task_scope (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword')),
    company_id  BIGINT REFERENCES companies(id) ON DELETE CASCADE,  -- kind='company'
    domain      TEXT,          -- root_domain / subdomain
    net         CIDR,          -- ip / cidr
    value       TEXT,          -- icp / keyword
    source      TEXT NOT NULL DEFAULT 'auto' CHECK (source IN ('auto','agent','manual')),
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 旧库升级：扩展任务范围，使其与企业范围的单文本框识别能力一致。
ALTER TABLE task_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE task_scope DROP CONSTRAINT IF EXISTS task_scope_kind_check;
ALTER TABLE task_scope ADD CONSTRAINT task_scope_kind_check
    CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword'));
-- 去重：同一 task 的同一条范围只存一次（自动填批量插入靠它幂等）。
DROP INDEX IF EXISTS uq_task_scope;
CREATE UNIQUE INDEX IF NOT EXISTS uq_task_scope_v2 ON task_scope(
    task_id, kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(company_id,0), COALESCE(value,''));
CREATE INDEX IF NOT EXISTS idx_ts_domain  ON task_scope(domain) WHERE kind IN ('root_domain','subdomain');
CREATE INDEX IF NOT EXISTS idx_ts_net     ON task_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE INDEX IF NOT EXISTS idx_ts_company ON task_scope(company_id) WHERE kind = 'company';

-- =====================================================================
-- E. Agents / 提示词模板 / 变量目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS agents (
    id                BIGSERIAL PRIMARY KEY,
    key               TEXT NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    name              TEXT NOT NULL,
    description       TEXT,
    role              TEXT NOT NULL,
    builtin           BOOLEAN NOT NULL DEFAULT true,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    llm_profile_id    BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    current_prompt_id BIGINT,
    max_turns         INTEGER NOT NULL DEFAULT 0,
    run_seconds       INTEGER NOT NULL DEFAULT 1200,
    web_search        BOOLEAN NOT NULL DEFAULT false,
    interactive_shell BOOLEAN NOT NULL DEFAULT false,
    wrapup_prompt     TEXT NOT NULL DEFAULT '',
    wrapup_max_turns  INTEGER NOT NULL DEFAULT 0,
    task_timeout_wrapup_prompt    TEXT NOT NULL DEFAULT '',
    task_timeout_wrapup_max_turns INTEGER NOT NULL DEFAULT 0,
    trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial'  CHECK (trigger_run_mode IN ('serial','parallel')),
    trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all' CHECK (trigger_merge_mode IN ('by_task','all','none')),
    trigger_max_parallel INTEGER NOT NULL DEFAULT 5,
    tool_base         TEXT    NOT NULL DEFAULT 'default' CHECK (tool_base IN ('default','none')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agents_role_ck CHECK (role IN ('goals','main','planner','worker','assistant'))
);
-- 加列迁移(已发版,旧库升级补列;新库 CREATE 已含。迁移不带 CHECK:旧库存量安全 + 后端写入白名单兜底)。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_max_parallel INTEGER NOT NULL DEFAULT 5;
-- 只读型 agent 执行底座开关(V4 安全面):'none'=装配时不注入 SDK DefaultTools(Bash/Read/Write…),
-- 仅保留 skills/MCP/hostTools 绑定增补。observer/reader seed 置 none;其余 agent 保持 default。
-- 迁移不带 CHECK(照 trigger_* 先例):旧库存量安全 + 后端写入白名单兜底。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tool_base TEXT NOT NULL DEFAULT 'default';
-- per-agent LLM 绑定(agent 级默认模型):列自初版即在上方 CREATE 中,此 ALTER 仅为极旧库兜底(幂等)。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
-- run_seconds 单次 run 墙钟默认 600→1200:只改列默认(影响将来新插入的行),不动旧库存量行。
ALTER TABLE agents ALTER COLUMN run_seconds SET DEFAULT 1200;
CREATE INDEX IF NOT EXISTS idx_agents_llm_profile ON agents(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_agents_upd ON agents;
CREATE TRIGGER trg_agents_upd BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS agent_prompts (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version       INT NOT NULL,
    template_text TEXT NOT NULL,
    note          TEXT,
    updated_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, version)
);
-- 循环外键：agents.current_prompt_id → agent_prompts.id（需在两表创建后加）
DO $$ BEGIN
    ALTER TABLE agents ADD CONSTRAINT fk_agents_curprompt
        FOREIGN KEY (current_prompt_id) REFERENCES agent_prompts(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_prompt_vars (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    var_name    TEXT NOT NULL,
    description TEXT,
    example     TEXT,
    source      TEXT NOT NULL CHECK (source IN ('exploration','runtime','distilled')),
    UNIQUE (agent_id, var_name)
);

-- =====================================================================
-- F. MCP 服务
-- =====================================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    transport   TEXT NOT NULL CHECK (transport IN ('stdio','http','sse')),
    command     TEXT,
    args        JSONB NOT NULL DEFAULT '[]',
    env         JSONB NOT NULL DEFAULT '{}',
    url         TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    insecure    BOOLEAN NOT NULL DEFAULT false,  -- http: 跳过 TLS 证书校验(自签证书场景, issue #108)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Allow legacy MCP SSE servers on databases created before SSE support.
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_transport_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_transport_check
    CHECK (transport IN ('stdio','http','sse'));
-- 旧库补列(schema.sql 每次启动都会 Exec)。
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS insecure BOOLEAN NOT NULL DEFAULT false;
DROP TRIGGER IF EXISTS trg_mcp_upd ON mcp_servers;
CREATE TRIGGER trg_mcp_upd BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 默认数据源占位：ScopeSentry 资产同步 MCP（地址与认证均留空、未启用）。
-- 供「资产同步」页检测数据源是否已配置；用户在页面填入 url 与 X-API-Key 后再启用。
-- 仅在缺失时插入，绝不覆盖用户已配置/已启用的服务器（schema.sql 每次启动都会 Exec）。
INSERT INTO mcp_servers (name, transport, url, env, enabled)
VALUES ('ScopeSentry', 'http', NULL, '{"X-API-Key":""}', false)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS mcp_tools_cache (
    id            BIGSERIAL PRIMARY KEY,
    server_id     BIGINT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    tool_name     TEXT NOT NULL,
    description   TEXT,
    schema        JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, tool_name)
);

-- =====================================================================
-- G. 可见性：agent × mcp / skill
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_visibility (
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_kind TEXT   NOT NULL CHECK (resource_kind IN ('mcp')),
    resource_id   BIGINT NOT NULL,
    mcp_tool_name TEXT   NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, resource_kind, resource_id, mcp_tool_name)
);
CREATE INDEX IF NOT EXISTS idx_vis_resource ON agent_visibility(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS agent_skill_visibility (
    agent_id   BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    skill_name TEXT   NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, skill_name)
);
CREATE INDEX IF NOT EXISTS idx_askv_skill ON agent_skill_visibility(skill_name);

-- Skill 调用账本（见 db/skill_usage.go）。一次 Skill() 调用一行，只记维度不记正文。
-- 刻意不设外键：任务/会话删除后统计仍要保留（与 llm_usage 同理），skill 本身也只是
-- 文件系统上的目录名，没有对应的表。
CREATE TABLE IF NOT EXISTS skill_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    skill          TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT,
    args_len       INTEGER NOT NULL DEFAULT 0,
    -- false = 模型点名了一个不存在的 skill(未命中)。这类行同样保留：它反映"想用但没有"
    -- 的缺口，是补 skill 的依据。
    found          BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_skill_usage_skill ON skill_usage(skill, ts DESC);
CREATE INDEX IF NOT EXISTS idx_skill_usage_task  ON skill_usage(task_id);

-- 工具调用账本（见 db/tool_usage.go）。一次实际 CoreTool.Call 一行，只记归属维度，
-- 不保存工具参数或返回内容。刻意不设外键，任务、会话或自定义工具删除后仍保留统计。
CREATE TABLE IF NOT EXISTS tool_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool_key       TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage(tool_key, ts DESC);
CREATE INDEX IF NOT EXISTS idx_tool_usage_task ON tool_usage(task_id);

-- =====================================================================
-- H. 内置工具目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS tools (
    key         TEXT PRIMARY KEY,
    system      BOOLEAN NOT NULL DEFAULT true,
    description TEXT    NOT NULL DEFAULT '',
    schema      JSONB   NOT NULL DEFAULT '{}',
    agents      JSONB   NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT    NOT NULL DEFAULT 'builtin',
    exec        JSONB   NOT NULL DEFAULT '{}',
    deferred    BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS trg_tools_upd ON tools;
CREATE TRIGGER trg_tools_upd BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- I. 会话（对话页）
-- =====================================================================
CREATE TABLE IF NOT EXISTS conversations (
    id             BIGSERIAL PRIMARY KEY,
    agent_key      TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    pinned_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_conversations_llm_profile ON conversations(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_conversations_pinned ON conversations(pinned_at DESC) WHERE pinned_at IS NOT NULL;
DROP TRIGGER IF EXISTS trg_conversations_upd ON conversations;
CREATE TRIGGER trg_conversations_upd BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS conversation_activities (
    id                 BIGSERIAL PRIMARY KEY,
    conversation_id    BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conv_act ON conversation_activities(conversation_id, id);
CREATE INDEX IF NOT EXISTS idx_conv_act_tool_call ON conversation_activities(conversation_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');

-- =====================================================================
-- J. Agent 触发器
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_triggers (
    id                          BIGSERIAL PRIMARY KEY,
    agent_key                   TEXT NOT NULL,
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    interval_sec                INTEGER NOT NULL DEFAULT 0,
    on_finding                  BOOLEAN NOT NULL DEFAULT false,
    on_goal_met                 BOOLEAN NOT NULL DEFAULT false,
    on_task_timeout             BOOLEAN NOT NULL DEFAULT false,
    on_tool_call                BOOLEAN NOT NULL DEFAULT false,
    on_task_create              BOOLEAN NOT NULL DEFAULT false,
    on_project_graph            BOOLEAN NOT NULL DEFAULT false,
    interval_message            TEXT NOT NULL DEFAULT '',
    finding_message             TEXT NOT NULL DEFAULT '',
    goal_message                TEXT NOT NULL DEFAULT '',
    task_timeout_message        TEXT NOT NULL DEFAULT '',
    tool_call_message           TEXT NOT NULL DEFAULT '',
    task_create_message         TEXT NOT NULL DEFAULT '',
    project_graph_message       TEXT NOT NULL DEFAULT '',
    tool_names                  TEXT NOT NULL DEFAULT '',
    last_fire                   TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_triggers_agent ON agent_triggers(agent_key);
-- 加列迁移(已发版,旧库升级补列;新库 CREATE 已含这些列,ALTER 为 no-op)。幂等,每次启动可重复执行。
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_tool_call        BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_call_message   TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_names          TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_task_create      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS task_create_message TEXT    NOT NULL DEFAULT '';
-- T11 观察者触发：某项目的探索图发生变更（project_graph_events 有新行且
-- 该项目 observer_enabled=true）时唤起 observer。project_graph_message 是该
-- 触发器的用户消息模板（与 finding_message 同形态：模板+引擎追加的变更清单）。
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_project_graph      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS project_graph_message TEXT    NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_agent_triggers_upd ON agent_triggers;
CREATE TRIGGER trg_agent_triggers_upd BEFORE UPDATE ON agent_triggers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS scheduler_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- =====================================================================
-- K. 拦截规则
-- =====================================================================
CREATE TABLE IF NOT EXISTS intercept_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 0,
    match_target    TEXT NOT NULL CHECK (match_target IN ('tool_name', 'tool_input')),
    match_type      TEXT NOT NULL CHECK (match_type IN ('string', 'regex')),
    pattern         TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask')),
    message         TEXT NOT NULL DEFAULT '',
    timeout_enabled BOOLEAN NOT NULL DEFAULT true,
    timeout_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_action  TEXT    NOT NULL DEFAULT 'deny',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DROP TRIGGER IF EXISTS trg_intercept_rules_upd ON intercept_rules;
CREATE TRIGGER trg_intercept_rules_upd BEFORE UPDATE ON intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS intercept_pending (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         BIGINT REFERENCES intercept_rules(id) ON DELETE SET NULL,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id         TEXT,
    agent_name      TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    tool_input      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'allowed', 'denied', 'timeout')),
    -- 判定理由:规则命中时为规则 message;LLM 兜底判定时为模型给的简短理由(前缀 [模型])。
    reason          TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_status ON intercept_pending(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_task   ON intercept_pending(task_id, created_at DESC);
-- 补旧库:reason 列(已发版,加列要带 IF NOT EXISTS)。
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
-- Detail payloads are lazy-loaded; NULL preserves the meaning of legacy history.
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS audit JSONB;
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decision_source TEXT NOT NULL DEFAULT '';
UPDATE intercept_pending SET decision_source=CASE WHEN rule_id IS NOT NULL THEN 'rule'
 WHEN reason LIKE '[模型]%' THEN 'model' ELSE 'unknown' END WHERE decision_source='';

-- =====================================================================
-- L. 漏洞发现持久化
-- =====================================================================
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    node_id     BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    vulnclass   TEXT NOT NULL DEFAULT '',
    -- 漏洞名称(可读标题)；为空时前端回退展示 vulnclass。severity 取值：
    -- critical 严重 / high 高 / medium 中 / low 低（不加 CHECK，与 status 一致由 server 白名单校验）。
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    worker      TEXT NOT NULL DEFAULT '',
    asset_ids   JSONB NOT NULL DEFAULT '[]',
    -- 处置状态：pending 待处理 / in_progress 处理中 / confirmed 已确认 / resolved 已处理 / fixed 已修复 /
    -- false_positive 误报 / ignored 忽略 / duplicate 重复 / risk_accepted 风险接受。
    -- 取值不加 CHECK：旧库靠下面的 ALTER 补列,CHECK 无法回填,统一由 server 侧白名单校验。
    status      TEXT NOT NULL DEFAULT 'pending',
    -- 漏洞详细报告(Markdown)；默认空,仅详情页读取/展示,不进列表接口以免 payload 膨胀。
    report      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS name   TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report TEXT NOT NULL DEFAULT '';
-- T14 结构化复现过程（reproduction）：entry_point/prerequisites/steps[request,response,
-- expected,proves,exchange_id]/provenance。JSONB，exchange_id 由落库时按任务时间窗
-- 自动关联流量回填（无则为空、view-time 再解析）。默认 '{}' = 未填（与空列语义区分，
-- 报告渲染据此判有无逐字复现）。
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reproduction JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_time ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, created_at DESC);
-- 「按资产」视图靠 asset_ids @> '[<id>]' 反查发现,没有这个 GIN 索引就是全表扫。
CREATE INDEX IF NOT EXISTS idx_findings_asset_ids ON findings USING GIN(asset_ids jsonb_path_ops);

-- 手动复测属于独立会话；结论与原漏洞处置状态分开保存。
CREATE TABLE IF NOT EXISTS finding_retests (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    conversation_id BIGINT UNIQUE REFERENCES conversations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','stopped')),
    verdict TEXT NOT NULL DEFAULT '' CHECK (verdict IN ('','reproduced','fixed','inconclusive')),
    notes TEXT NOT NULL DEFAULT '',
    snapshot JSONB NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_finding_retests_history ON finding_retests(finding_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_retests_active ON finding_retests(finding_id)
    WHERE status IN ('pending','running');

-- 删除会话保留复测记录，同时解除尚未结束的复测占用。
CREATE OR REPLACE FUNCTION stop_deleted_conversation_retest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE finding_retests SET status='stopped', error='复测会话已删除', finished_at=now()
    WHERE conversation_id=OLD.id AND status IN ('pending','running');
    RETURN OLD;
END;
$$;
DROP TRIGGER IF EXISTS trg_conversation_retest_delete ON conversations;
CREATE TRIGGER trg_conversation_retest_delete BEFORE DELETE ON conversations
    FOR EACH ROW EXECUTE FUNCTION stop_deleted_conversation_retest();

ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report_evidence_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS traffic_evidence_snapshots (
    id TEXT PRIMARY KEY,
    source_traffic_id TEXT NOT NULL,
    captured_at BIGINT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    req_head TEXT NOT NULL,
    resp_head TEXT NOT NULL,
    req_hash TEXT NOT NULL,
    resp_hash TEXT NOT NULL,
    req_len BIGINT NOT NULL,
    resp_len BIGINT NOT NULL,
    unreferenced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_traffic_bindings (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES traffic_evidence_snapshots(id),
    role TEXT NOT NULL DEFAULT 'supporting',
    note TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(finding_id, snapshot_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_order ON finding_traffic_bindings(finding_id, position, id);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_snapshot ON finding_traffic_bindings(snapshot_id);

-- =====================================================================
-- M. 后端日志持久化
-- =====================================================================
CREATE TABLE IF NOT EXISTS server_logs (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    level      TEXT NOT NULL DEFAULT 'info',
    tag        TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_server_logs_id ON server_logs(id DESC);

-- Independent /btw history and the latest provider-ready main checkpoint.
CREATE TABLE IF NOT EXISTS side_question_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    exploration_id BIGINT REFERENCES explorations(id) ON DELETE CASCADE,
    intent_id BIGINT REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    run_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    CHECK ((conversation_id IS NOT NULL AND task_id IS NULL AND exploration_id IS NULL AND intent_id IS NULL)
        OR (conversation_id IS NULL AND task_id IS NOT NULL AND exploration_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_side_sessions_conv ON side_question_sessions(conversation_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_task ON side_question_sessions(task_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_exp ON side_question_sessions(exploration_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_intent ON side_question_sessions(intent_id);

CREATE TABLE IF NOT EXISTS side_question_requests (
    id TEXT PRIMARY KEY,
    ordinal BIGSERIAL UNIQUE,
    session_key TEXT NOT NULL REFERENCES side_question_sessions(session_key) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    client_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed','cancelled','interrupted')),
    error TEXT NOT NULL DEFAULT '',
    model JSONB NOT NULL,
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence BIGINT NOT NULL DEFAULT 0,
    usage JSONB NOT NULL DEFAULT '{}',
    UNIQUE(session_key,generation,client_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_side_request_running ON side_question_requests(session_key) WHERE status='running';
CREATE INDEX IF NOT EXISTS idx_side_requests_history ON side_question_requests(session_key,ordinal DESC);

-- Additive v3 archive fields; old archives restore these as empty objects.
ALTER TABLE side_question_sessions ADD COLUMN IF NOT EXISTS memory JSONB NOT NULL DEFAULT '{}';
ALTER TABLE side_question_requests ADD COLUMN IF NOT EXISTS context_info JSONB NOT NULL DEFAULT '{}';

-- =====================================================================
-- 资产拦截规则（全局黑名单）
-- 独立于 §K 命令拦截(intercept_rules)：intercept_rules 匹配工具名/入参文本，
-- 这张表匹配「目标资产」——全等/模糊的域名·IP·URL 以及 CIDR 网段。
-- 仅存规则；具体的匹配/拦截逻辑在别处实现。
-- kind 七种：
--   exact_domain / exact_ip / exact_url  —— 全等匹配
--   fuzzy_domain / fuzzy_ip / fuzzy_url  —— 模糊匹配
--   cidr                                 —— CIDR 网段
-- =====================================================================
CREATE TABLE IF NOT EXISTS asset_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_intercept_enabled ON asset_intercept_rules(enabled);
DROP TRIGGER IF EXISTS trg_asset_intercept_rules_upd ON asset_intercept_rules;
CREATE TRIGGER trg_asset_intercept_rules_upd BEFORE UPDATE ON asset_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 任务级资产拦截/允许规则
-- 与全局 asset_intercept_rules 同构（kind/pattern/note/enabled），但按 task_id
-- 关联、随任务级联删除；创建任务时录入、任务详情里可编辑。
-- action: 'block'=拦截(禁止测试)  'allow'=允许(白名单)。
-- 执行判定：先按 拦截规则(全局 ∪ 任务block) 匹配，命中即禁止；未命中且该任务存在
-- 启用的 allow 规则时，须命中某条 allow 才放行，否则「不允许测试」。
-- =====================================================================
CREATE TABLE IF NOT EXISTS task_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    action      TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block','allow')),
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_task_intercept_task ON task_intercept_rules(task_id);
-- 补旧库(本会话早前建过该表、无 action 列)：加列(带 IF NOT EXISTS)。
ALTER TABLE task_intercept_rules ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'block';
DROP TRIGGER IF EXISTS trg_task_intercept_rules_upd ON task_intercept_rules;
CREATE TRIGGER trg_task_intercept_rules_upd BEFORE UPDATE ON task_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- M. 漏洞 IM 推送
--
-- 三张表刻意分开，核心是**爆炸半径**：写漏洞的那个事务(RecordFindingTx，
-- 持任务行锁)只允许做一次盲 INSERT，不读渠道表、不跑用户的过滤规则。否则
-- 一条配错的 webhook 过滤条件就能污染/中止事务，导致漏洞存不进去。
--
--   notification_channels   渠道实例配置(可变、含凭据、UI 管理)
--   notification_events     事件事实(写漏洞事务内盲插，含渲染快照)
--   notification_deliveries 投递任务(事务外 fan-out 产生，承载状态/重试/批次)
-- =====================================================================

-- 渠道实例：同一 kind 可配任意多个(如「应急群」「日常群」各一个钉钉机器人)。
-- kind 取值由 server 侧白名单校验，不加 CHECK：与 findings.status 同理，
-- 后续加渠道不应要求改表结构。
CREATE TABLE IF NOT EXISTS notification_channels (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    -- dingtalk 钉钉 / feishu 飞书 / wecom 企业微信 / webhook 通用 / telegram / email
    kind         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    -- 凭据(明文存储，UI 掩码回显；见 server 侧 maskChannelSecrets)。六种渠道字段差异极大，
    -- 统一 JSONB + Go 侧按 kind 严格校验，避免为每渠道加一堆 NULL 列：
    --   dingtalk {webhook,secret}
    --   feishu   {webhook,secret}
    --   wecom    {webhook}
    --   webhook  {url,method,content_type,headers{},body_template}
    --   telegram {bot_token,chat_id,base_url}
    --   email    {host,port,username,password,from,to[],tls}
    config       JSONB NOT NULL DEFAULT '{}',
    -- 推送时机：realtime 命中即推 / digest 进批次按全局周期汇总成一条。
    mode         TEXT NOT NULL DEFAULT 'realtime',
    -- 过滤条件，字段全部可选(缺省=不过滤)：
    --   min_severity       ''|low|medium|high|critical
    --   task_ids/asset_ids 空数组=不限；非空则须交集非空
    --   vulnclass_include/exclude 关键词数组(大小写不敏感子串)；include 空=全收
    --   on_status_change   bool，仅 realtime 模式有意义
    filter       JSONB NOT NULL DEFAULT '{}',
    -- 每分钟投递上限；0=不限流。默认 20 对齐钉钉/企微官方硬限。
    -- 超限不丢消息，只把投递推迟到下一个 tick。
    rate_per_min INTEGER NOT NULL DEFAULT 20,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS trg_notification_channels_upd ON notification_channels;
CREATE TRIGGER trg_notification_channels_upd BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 事件事实。由 RecordFindingTx / 状态变更事务**同事务**写入，保证「漏洞落库」
-- 与「推送任务存在」原子一致——不存在提交成功但没入队、消息永久丢失的窗口。
-- snapshot 刻意冗余：漏洞事后会被改名/改级别/改状态，推送内容应反映「事发当时」，
-- 且 fan-out 与渲染不必回查 findings/tasks/assets 多张表。
-- finding 删除后事件不级联删除：与 findings 表「任务删除仍独立留存」的语义一致。
CREATE TABLE IF NOT EXISTS notification_events (
    id         BIGSERIAL PRIMARY KEY,
    -- finding_created | finding_status_changed
    kind       TEXT NOT NULL,
    finding_id BIGINT NOT NULL,
    snapshot   JSONB NOT NULL,
    -- fan-out 幂等标记：dispatcher 按此列取待分派事件，处理完置 true。
    -- 用列而非删行，以便投递历史能回溯到事件。
    fanned_out BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_events_pending
    ON notification_events(id) WHERE NOT fanned_out;

-- 投递任务：一条事件 × 一个启用渠道 = 一行。fan-out 在事务外做，所以渠道
-- 后开不会补历史(与 agent_triggers 的「迟开 trigger 不补历史」语义一致，
-- 避免启用渠道时一次性刷屏历史积压)。
-- channel_id 级联删除：渠道配置都没了，其投递历史无意义。
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id          BIGSERIAL PRIMARY KEY,
    event_id    BIGINT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
    channel_id  BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    -- pending 待发 / sent 已发 / failed 重试耗尽(可手动重发) / skipped 渠道停用或批次取消
    -- pending 待发 / sending 已被某 dispatcher 领取(租约未到期) / sent 已发 /
    -- failed 重试耗尽或永久失败(可手动重发) / skipped 渠道停用。取值不加 CHECK，
    -- 与 findings.status 同理，由 server 侧白名单校验。
    state       TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    -- 兼作「下次可领取时间」与「租约到期时间」：领取时把它推到未来即构成租约，
    -- 于是「租约未到期」与「未到重试时间」共用同一个条件表达，不需要额外的
    -- lease_until 列。进程崩溃留下的 sending 行会因租约到期被下一轮重新领取。
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error  TEXT NOT NULL DEFAULT '',
    -- digest 模式同批次共享；realtime 恒为 NULL。整批渲染成一条消息后一起置 sent。
    batch_id    BIGINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_due
    ON notification_deliveries(next_attempt_at) WHERE state='pending';
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_history
    ON notification_deliveries(id DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_batch
    ON notification_deliveries(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel
    ON notification_deliveries(channel_id, id DESC);

-- =====================================================================
-- M. 审计链（T02 红线吸收）
-- =====================================================================
-- 平台自身的安全判定（deny / ask / timeout）按顺序追加的哈希链。
-- 每条的 digest 都把上一条的 digest 算进去，改动任何一条都会让后续链条对不上。
-- 与 intercept_pending 互补：那张表的行可以直接被 UPDATE 掉，链能报出断在第几条。
CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    seq         BIGINT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    tool_name   TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    -- 存 TEXT 而不是 JSONB：JSONB 落库会重排键、改空白，读回来的字节与写入
    -- 时不同，链的 digest 就会误报断裂。审计链要的是字节级可复算。
    payload     TEXT NOT NULL DEFAULT '{}',
    digest      TEXT NOT NULL,
    prev_digest TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_seq ON audit_events(seq);

-- =====================================================================
-- N. 项目-任务两级模型（artex-hs F1/F2，T05）
-- =====================================================================
-- 项目主表。二开新增，与原版任务体系松耦合：任务通过 tasks.project_id 可选归属。
CREATE TABLE IF NOT EXISTS projects (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL,                        -- 项目名（报告封面/标题用）
    description       TEXT NOT NULL DEFAULT '',             -- 项目描述/测试范围说明
    status            TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','archived')),
    owner             TEXT NOT NULL DEFAULT '',             -- 负责人，可留空
    concurrency       INTEGER NOT NULL DEFAULT 2,           -- 项目内批量任务并发数：1=严格串行，2=同时两任务
    observer_enabled  BOOLEAN NOT NULL DEFAULT false,       -- 观察者开关：默认关闭。[T12 定稿]只管两件事：触发 observer + 注入 insight；project_index 投影常开（大图 tab 数据源，关着也能看）
    report_template_id BIGINT,                             -- 项目默认报告模板（report_templates.id）；NULL=走默认模板链。无 FK：模板行允许被删（view-time/建 job 时判缺回退默认，照 tasks.template_id 同款策略）
    auto_report       BOOLEAN NOT NULL DEFAULT false,      -- 整项目收官自动写报告：默认关闭。任务终态钩子查此开关决定是否建 project 级报告 job（T18）
    reader_enabled    BOOLEAN NOT NULL DEFAULT false,      -- 允许跨项目 reader 聚合本项目洞察：默认关闭=行为等于基线（T18）
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_projects_alive ON projects(created_at DESC) WHERE status='active';
DROP TRIGGER IF EXISTS trg_projects_upd ON projects;
CREATE TRIGGER trg_projects_upd BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 任务归属项目；NULL=无项目（完全等价原版行为，零回归基线）。
-- 刻意 ON DELETE SET NULL：删项目不连带删任务（任务数据比项目分组更贵重）。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL;
-- T18 项目设置扩展三列（CREATE 内+ALTER 双写，schema.go:171 exec 整份、
-- 幂等约束照 :249-255 写法；新库走 CREATE、存量库走 ALTER，语义一致）。
ALTER TABLE projects ADD COLUMN IF NOT EXISTS report_template_id BIGINT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS auto_report BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS reader_enabled BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id, created_at DESC)
    WHERE deleted_at IS NULL AND project_id IS NOT NULL;
-- 批量调度取「某项目 FIFO 队首」用（partial 只索引在排队的行，命中集小）：
CREATE INDEX IF NOT EXISTS idx_tasks_project_queued ON tasks(project_id, queued_at ASC)
    WHERE deleted_at IS NULL AND queued = true AND project_id IS NOT NULL;

-- =====================================================================
-- O. 项目大图 + 观察者/阅读者（artex-hs F2，T09）
-- =====================================================================
-- projects.observer_enabled 列已在 §N 建表语句内（T05 起即有），无需 ALTER 补。
-- 本段四表：节点投影索引 / 图变更事件 / 项目洞察 / 全局洞察。

-- 任务图节点的"项目级摘要投影"。不复制整图，只存可供 observer 总览的摘要行。
-- planner/worker 每轮读各自 exploration 原图（graphOverviewData 零改动），只旁路写投影。
-- project_id 刻意不加 FK：回调侧（server 闭包）已按 task_id→project_id 解析并校验
-- 项目存在+开关，热路径不再回查；投影清理本就异步（见 task_id 注释同理）。
CREATE TABLE IF NOT EXISTS project_index (
    id             BIGSERIAL PRIMARY KEY,
    project_id     BIGINT NOT NULL,                        -- 所属项目（无 FK，见上注）
    task_id        BIGINT NOT NULL,                        -- 冗余任务 id（不 FK，任务删除后投影清理走异步，别级联卡删除事务）
    node_id        BIGINT NOT NULL,                        -- exploration_nodes.id
    kind           TEXT NOT NULL,                          -- begin|goal|intent|fact|finding|hint|digest
    state          TEXT NOT NULL DEFAULT '',               -- 节点终态快照（intent done/blocked…、goal met…）；事件驱动刷新
    summary        TEXT NOT NULL DEFAULT '',               -- 一行摘要（供 observer/大图列表）
    asset_keys     TEXT[] NOT NULL DEFAULT '{}',           -- 关联资产键（域名/IP/URL 归一化），跨任务相似命中主键
    severity       TEXT NOT NULL DEFAULT '',               -- finding 专用：critical|high|medium|low（非 finding 为空）
    payload_digest JSONB NOT NULL DEFAULT '{}',            -- 摘要载荷（state/confidence/vulnclass/关键词等，够总览不够再展原图）
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 幂等 upsert 键：同一节点在一个项目里只有一行。用显式唯一索引（而非表内 UNIQUE
-- 约束）建，索引名与 ON CONFLICT 目标一致，旧库/新库都稳定可寻。
CREATE UNIQUE INDEX IF NOT EXISTS ux_pidx_proj_node ON project_index(project_id, node_id);
CREATE INDEX IF NOT EXISTS idx_pidx_proj_kind ON project_index(project_id, kind);
CREATE INDEX IF NOT EXISTS idx_pidx_proj_sev  ON project_index(project_id, severity) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_pidx_proj_task ON project_index(project_id, task_id);
CREATE INDEX IF NOT EXISTS idx_pidx_asset     ON project_index USING GIN(asset_keys);   -- 资产交集命中（insight 匹配/observer 查同类）
DROP TRIGGER IF EXISTS trg_pidx_upd ON project_index;
CREATE TRIGGER trg_pidx_upd BEFORE UPDATE ON project_index
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 图变更事件"事实表"，供 scheduler 按水位增量扫，唤醒 observer。与 findings→
-- notification_events 同构（只追加、消费后靠水位线推进，不删行）。
-- 列集为任务书（task-lead）与架构 §1.4 的并集：node_id/kind 定位变更节点，
-- delta_summary 喂 observer 触发上下文（"task#7 新增 finding[high] SQLi@/api/user"）。
CREATE TABLE IF NOT EXISTS project_graph_events (
    id            BIGSERIAL PRIMARY KEY,
    project_id    BIGINT NOT NULL,                         -- 所属项目（同上，无 FK）
    task_id       BIGINT NOT NULL,                         -- 变更源任务
    node_id       BIGINT,                                  -- 变更节点（可空：批量/摘要类事件不锚定单节点）
    kind          TEXT NOT NULL DEFAULT '',                -- 变更节点 kind（intent/fact/finding/goal/hint…）
    delta_summary TEXT NOT NULL DEFAULT '',                -- 一行变更摘要，喂 observer
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()       -- 事件发生时间（水位扫描按 id，不用此列）
);
CREATE INDEX IF NOT EXISTS idx_pge_scan ON project_graph_events(project_id, id);  -- 水位 WHERE project_id=$1 AND id>$last ORDER BY id

-- 统一阅读者洞察表（V6-U1）：一套表用 scope 区分两种作用域——
--   scope='project'：项目洞察，project_id 指向所属项目（随项目级联删），
--                    keywords/source_task_id 是命中键与来源任务；
--   scope='cross'  ：跨项目洞察，project_id=NULL（不挂任何项目、不被级联删），
--                    source_projects/asset_keys 供跨项目注入命中。
-- 「WHERE project_id=$1」的既有 API 因 cross 行 project_id=NULL 天然隔离，
-- 不需要视图。status 生命周期（active/rejected/superseded）对两种 scope 通用。
CREATE TABLE IF NOT EXISTS project_insights (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT REFERENCES projects(id) ON DELETE CASCADE, -- cross 行置 NULL（不挂项目）；project 行随项目级联删
    content         TEXT NOT NULL,                         -- 洞察正文
    source_task_id  BIGINT,                                -- project 行：触发写此洞察时正看的任务
    keywords        TEXT[] NOT NULL DEFAULT '{}',          -- project 行：与 planner 命中匹配用
    scope           TEXT NOT NULL DEFAULT 'project'
                      CHECK (scope IN ('project','cross')),
    source_projects BIGINT[] NOT NULL DEFAULT '{}',        -- cross 行：串联涉及的 project id
    asset_keys      TEXT[] NOT NULL DEFAULT '{}',          -- cross 行：注入命中键（归一化资产键）
    superseded_by   BIGINT,                                -- cross 行：覆盖本行的新洞察 id
    status          TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','rejected','superseded')),
    rejected_reason TEXT NOT NULL DEFAULT '',              -- 否决原因（人工/planner 留痕，供复核）
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pins_proj ON project_insights(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pins_kw   ON project_insights USING GIN(keywords);
-- 注：idx_pins_status / idx_pins_scope / idx_pins_asset 依赖 status/scope/asset_keys
-- 列，存量库上必须在下方 ALTER ADD COLUMN 之后建，见「存量库补列」段末。

-- V6 之前的跨项目洞察表（遗留）。DDL 保留的理由：① 全新库与存量库走同一套
-- 幂等重放；② TestSchemaContainsProjectGraphTables 的 DDL 字面锚点；③ 迁移时
-- 从它逐行读出存量数据。迁移完成后本表由下方 DO 块改名归档
-- （global_insights_archive_20261113），Go 层（V6-U2 起）不再读写它——所有读写
-- 都走 project_insights 且带 scope='cross'。改名后每次启动的 CREATE IF NOT
-- EXISTS 会重建一个空壳表，无害（无数据、无代码引用），仅为幂等。
-- asset_keys 是与 planner 命中键同源的归一化键集合；superseded_by 指新 id。
CREATE TABLE IF NOT EXISTS global_insights (
    id              BIGSERIAL PRIMARY KEY,
    content         TEXT NOT NULL,                         -- 洞察正文
    source_projects BIGINT[] NOT NULL DEFAULT '{}',        -- 串联涉及的 project id 列表
    asset_keys      TEXT[] NOT NULL DEFAULT '{}',          -- 注入命中键（与任务 open 意图锚定资产求交集）
    status          TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','rejected','superseded')),
    superseded_by   BIGINT,                                -- 覆盖本行的新洞察 id（status='superseded' 时）
    rejected_reason TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gins_time ON global_insights(created_at DESC);
-- 注：idx_gins_keys 依赖 asset_keys 列，存量库上必须在下方 ALTER ADD COLUMN 之后建，见「存量库补列」段末。

-- 存量库补列（幂等；CREATE 段已含同名列，双写法照 projects/finding_evidence_images 先例）。
-- 旧的 status/rejected_reason 补列（V5-A 遗产）保留，供更早的存量库逐级升级。
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS rejected_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE global_insights ADD COLUMN IF NOT EXISTS asset_keys TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE global_insights ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE global_insights ADD COLUMN IF NOT EXISTS superseded_by BIGINT;
ALTER TABLE global_insights ADD COLUMN IF NOT EXISTS rejected_reason TEXT NOT NULL DEFAULT '';
-- V6-U1 统一阅读者：project_insights 补 scope 分区列（双写法同 CREATE 段）。
-- 存量库旧行补列后 scope='project'（项目洞察保持原语义）。
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'project';
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS source_projects BIGINT[] NOT NULL DEFAULT '{}';
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS asset_keys TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE project_insights ADD COLUMN IF NOT EXISTS superseded_by BIGINT;
-- cross 行 project_id=NULL（不挂任何项目），故解除原 NOT NULL。
ALTER TABLE project_insights ALTER COLUMN project_id DROP NOT NULL;
-- 存量库上补 status 取值约束（ALTER ADD CONSTRAINT 不支持 IF NOT EXISTS，照 assets 先例先 DROP）。
ALTER TABLE project_insights DROP CONSTRAINT IF EXISTS project_insights_status_check;
ALTER TABLE project_insights ADD CONSTRAINT project_insights_status_check
    CHECK (status IN ('active','rejected','superseded'));
ALTER TABLE global_insights DROP CONSTRAINT IF EXISTS global_insights_status_check;
ALTER TABLE global_insights ADD CONSTRAINT global_insights_status_check
    CHECK (status IN ('active','rejected','superseded'));
-- scope 取值约束同样先 DROP 再 ADD（幂等）。
ALTER TABLE project_insights DROP CONSTRAINT IF EXISTS project_insights_scope_check;
ALTER TABLE project_insights ADD CONSTRAINT project_insights_scope_check
    CHECK (scope IN ('project','cross'));
-- 依赖新列（status/scope/asset_keys）的索引必须在补列之后创建：存量库上
-- CREATE TABLE IF NOT EXISTS 是空操作，表里还没有这些列，前置建索引会
-- 直接报 42703 导致启动失败（V5 部署实测踩到，全新库不暴露）。
CREATE INDEX IF NOT EXISTS idx_gins_keys ON global_insights USING GIN(asset_keys);
CREATE INDEX IF NOT EXISTS idx_pins_status ON project_insights(project_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gins_status ON global_insights(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pins_scope ON project_insights(scope, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pins_asset ON project_insights USING GIN(asset_keys);

-- =====================================================================
-- V6-U1 统一阅读者一次性迁移：存量 global_insights 逐行并入
-- project_insights(scope='cross')，原表改名 global_insights_archive_20261113
-- 留回滚（不 DROP）。以「归档表是否存在」为哨兵，归档后每次启动重放本文件
-- 都直接短路——迁移与 superseded_by 重映射绝不重复。
-- =====================================================================
DO $$
DECLARE
    r      record;
    new_id bigint;
BEGIN
    IF to_regclass('public.global_insights_archive_20261113') IS NOT NULL THEN
        RETURN; -- 已迁移：幂等短路
    END IF;
    IF to_regclass('public.global_insights') IS NULL THEN
        RETURN; -- 无遗留表（全新库理论上不会走到这里）
    END IF;

    -- 逐行插入单表并记 old→new 映射：cross 行 project_id=NULL，其余字段
    -- （content/source_projects/asset_keys/status/rejected_reason/created_at）原样保留。
    CREATE TEMP TABLE _v6_pins_map(old_id bigint PRIMARY KEY, new_id bigint) ON COMMIT DROP;
    FOR r IN SELECT id, content, source_projects, asset_keys, status,
                    superseded_by, rejected_reason, created_at
             FROM global_insights ORDER BY id LOOP
        INSERT INTO project_insights(project_id, content, source_task_id, keywords,
                                     scope, source_projects, asset_keys, status,
                                     superseded_by, rejected_reason, created_at)
        VALUES (NULL, r.content, NULL, '{}', 'cross', r.source_projects, r.asset_keys,
                r.status, r.superseded_by, r.rejected_reason, r.created_at)
        RETURNING id INTO new_id;
        INSERT INTO _v6_pins_map(old_id, new_id) VALUES (r.id, new_id);
    END LOOP;

    -- 重映射 superseded_by：旧值指向 global_insights 的 id，改成迁移后的新行 id。
    -- 只在 scope='cross' 行上做，绝不碰项目洞察；悬空旧 id（无映射）保留原样。
    UPDATE project_insights pi SET superseded_by = m.new_id
    FROM _v6_pins_map m
    WHERE pi.scope = 'cross' AND pi.superseded_by = m.old_id;

    -- 语义 A（一开全开，用户要测统一阅读者的作用）：存量项目把兼容别名
    -- reader_enabled 对齐到主开关 observer_enabled。放在一次性迁移里，之后
    -- 用户经 API 改开关会镜像写两列，不会被这里覆盖。
    UPDATE projects SET reader_enabled = observer_enabled;

    -- 归档留回滚：改名而不 DROP；同时释放 serial sequence 名，避免下次启动
    -- CREATE TABLE IF NOT EXISTS global_insights 重建空表时 sequence 撞名报错。
    ALTER TABLE global_insights RENAME TO global_insights_archive_20261113;
    ALTER SEQUENCE IF EXISTS global_insights_id_seq RENAME TO global_insights_archive_20261113_id_seq;
END $$;

-- =====================================================================
-- P. 报告中心（artex-hs F4，T15）：报告模板 / 生成 job+历史 / 全局设置
-- =====================================================================
-- 三表分工：report_templates=可复用的封面/章节骨架/样式/AI prompt 预设；
-- reports=「job+历史」一体（生成任务的状态机行，成功后 file_path 即交付物）；
-- report_settings=全局单例（默认模板引用 + 默认输出语言）。
-- 渲染实现本棒为 Markdown 桩（server/reportgen.go 的 ReportRenderer 挂点），
-- T16 换 pybuilder docx 实装，表结构不变。

-- 报告模板。skeleton 是章节骨架：有序数组 [{"key","title","enabled"}]，
-- key 枚举起步 cover|statement|targets|summary|vuln_detail|conclusion，
-- 校验/归一化纯函数见 db.ValidateSkeleton / db.NormalizeSkeleton
-- （列默认 '{}' = 旧行未初始化，读取时归一化为默认全章节骨架）。
-- style=字体/字号等渲染样式参数（T16 pybuilder 消费）；prompts=按章节 key
-- 组织的 AI 叙述模板；personnel=[{name,role,contact}]。
CREATE TABLE IF NOT EXISTS report_templates (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,                              -- 模板名（报告中心列表展示）
    is_default   BOOLEAN NOT NULL DEFAULT false,             -- 全局默认模板（至多一行 true，SetDefaultTemplate 单事务维护）
    output_lang  TEXT NOT NULL DEFAULT 'zh-CN',              -- 默认输出语言（locale；生成入参可覆盖）
    skeleton     JSONB NOT NULL DEFAULT '{}',                -- 章节骨架数组 [{key,title,enabled}]；'{}'=未初始化→读取时归一化为默认
    style        JSONB NOT NULL DEFAULT '{}',                -- 字体/字号等样式（T16 pybuilder 消费）
    prompts      JSONB NOT NULL DEFAULT '{}',                -- AI 叙述 prompt（按章节 key 组织）
    issuer       TEXT NOT NULL DEFAULT '',                   -- 出具方（封面）
    logo_path    TEXT NOT NULL DEFAULT '',                   -- logo 相对 dataDir 路径（封面）
    personnel    JSONB NOT NULL DEFAULT '[]',                -- 参测人员表 [{name,role,contact}]
    cvss_enabled BOOLEAN NOT NULL DEFAULT false,             -- 报告中是否呈现 CVSS 评分
    remark       TEXT NOT NULL DEFAULT '',                   -- 备注（模板用途说明等）
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_report_tpl_default ON report_templates(is_default) WHERE is_default;
DROP TRIGGER IF EXISTS trg_report_tpl_upd ON report_templates;
CREATE TRIGGER trg_report_tpl_upd BEFORE UPDATE ON report_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 报告生成 job + 交付历史（一体）。状态机 pending→running→done|failed，
-- 非法迁移由 AdvanceReportStatus 拒绝（矩阵纯函数 CanAdvanceReport 单测覆盖）。
-- task_ids/project_id 二选一（CHECK 保证与 scope 一致）；finding_ids 为勾选子集
-- （空数组=任务/项目内全部 findings）。error/warning 存截断后的文本
-- （warning 例：伪资产反向校验剔除清单，见 report.FilterPseudoTargets）。
CREATE TABLE IF NOT EXISTS reports (
    id           BIGSERIAL PRIMARY KEY,
    scope        TEXT NOT NULL CHECK (scope IN ('task','project')),  -- 报告粒度：单任务/项目汇总
    task_ids     BIGINT,                              -- scope='task'：来源任务 id
    project_id   BIGINT,                              -- scope='project'：来源项目 id
    template_id  BIGINT,                              -- 所用模板；NULL=取全局默认模板
    locale       TEXT NOT NULL DEFAULT 'zh-CN',       -- 输出语言（入参>模板>zh-CN）
    format       TEXT NOT NULL DEFAULT 'docx',        -- 交付格式 docx|md（本棒两种都走桩）
    status       TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','running','done','failed')),
    file_path    TEXT NOT NULL DEFAULT '',            -- 产物绝对路径（done 后非空）
    error        TEXT NOT NULL DEFAULT '',            -- failed 原因（入库前截断）
    warning      TEXT NOT NULL DEFAULT '',            -- 成功但带警示（如剔除伪目标）
    finding_ids  BIGINT[] NOT NULL DEFAULT '{}',      -- 勾选的 finding 子集；'{}'=全部
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),  -- 入队（pending）时刻
    started_at   TIMESTAMPTZ,                         -- 迁移到 running 时刻
    finished_at  TIMESTAMPTZ,                         -- 迁移到 done/failed 时刻
    CONSTRAINT ck_reports_scope_key CHECK (
        (scope = 'task'    AND task_ids IS NOT NULL AND project_id IS NULL) OR
        (scope = 'project' AND project_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_reports_status_time ON reports(status, created_at DESC);

-- 报告全局设置（单例表：key 恒 'default'）。template_id=NULL → 用 is_default 模板。
CREATE TABLE IF NOT EXISTS report_settings (
    key            TEXT PRIMARY KEY DEFAULT 'default',  -- 单例哨兵值，恒 'default'
    template_id    BIGINT,                              -- 全局默认报告模板（NULL=回退 is_default 行）
    default_locale TEXT NOT NULL DEFAULT 'zh-CN'        -- 未显式指定 locale 时的输出语言
);

-- =====================================================================
-- Q. 发现证据截图（artex-hs F4，T16(3/3)）：漏洞详情页逐步骤上传的截图
-- =====================================================================
-- 派工书列名写作 finding_node_id，但 0.3.15 所有 findings 子表
-- （finding_retests / finding_traffic_bindings）与发现详情页句柄统一用
-- findings 表 id（FindingDTO 未透出探索节点 id，detail 页 ?id= 即 findings.id）。
-- 为与兄弟表一致、外键可 ON DELETE CASCADE 随漏洞存亡，这里键定为 finding_id
-- （值=findings.id），列名偏差已上报 team-lead 待裁决。step_index 对应
-- report.Reproduction.Steps 下标（从 1 计；0=漏洞级证据，不锚定单步）。
-- filename 是相对 dataDir 的存储路径（data/report_assets/evidence/<fid>/<nano>），
-- 静态服务按 id 反查后 ServeFile（不落可猜路径、防穿越）。sort_order 同步骤内排序。
CREATE TABLE IF NOT EXISTS finding_evidence_images (
    id          BIGSERIAL PRIMARY KEY,
    finding_id  BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, -- 值=findings.id（见上注）
    step_index  INTEGER NOT NULL DEFAULT 0,           -- 复现步骤下标(从1计)；0=漏洞级
    filename    TEXT NOT NULL,                         -- 相对 dataDir 的存储路径
    caption     TEXT NOT NULL DEFAULT '',             -- 图注（可空）
    sort_order  INTEGER NOT NULL DEFAULT 0,           -- 同步骤内展示序
    source      TEXT NOT NULL DEFAULT 'upload',       -- T22：auto=报文自动截图 / paste / upload（存量行默认 upload 兼容）
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fei_finding ON finding_evidence_images(finding_id, step_index, sort_order, id);
-- T22 报文自动截图：旧库补 source 列（CREATE 段已含，双写法同 projects 三列先例）。
ALTER TABLE finding_evidence_images ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'upload';
