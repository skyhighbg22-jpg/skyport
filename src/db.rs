use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use rusqlite::{params, params_from_iter, types::Value as SqlValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const TELEMETRY_KEYRING_ACCOUNT: &str = "telemetry_database_key";
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// A single request log row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: Option<i64>,
    pub timestamp: String,
    pub provider: String,
    pub key_alias: String,
    pub model: String,
    pub status: i32,
    pub latency_ms: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub est_cost_usd: f64,
}

/// Aggregate statistics for a time range.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestStats {
    pub total_requests: i64,
    pub total_tokens: i64,
    pub total_cost_usd: f64,
    pub avg_latency_ms: f64,
    pub error_count: i64,
    pub by_provider: HashMap<String, ProviderStats>,
    pub by_model: HashMap<String, ProviderStats>,
}

/// Per-provider statistics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderStats {
    pub requests: i64,
    pub tokens: i64,
    pub cost_usd: f64,
    pub avg_latency_ms: f64,
}

/// Optional constraints for querying request telemetry. Timestamps use Unix
/// milliseconds at the API boundary, then become RFC3339 strings for SQLite.
#[derive(Clone, Debug, Default)]
pub struct LogFilter {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub key_alias: Option<String>,
    pub status: Option<String>,
    pub min_cost: Option<f64>,
    pub max_cost: Option<f64>,
    pub min_latency: Option<i64>,
    pub max_latency: Option<i64>,
    pub min_tokens: Option<i64>,
    pub max_tokens: Option<i64>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub query: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficTotals {
    pub total_requests: i64,
    pub total_tokens: i64,
    pub total_cost_usd: f64,
    pub avg_latency_ms: f64,
    pub error_count: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficBreakdown {
    pub group: String,
    pub requests: i64,
    pub tokens: i64,
    pub cost_usd: f64,
    pub avg_latency_ms: f64,
    pub error_count: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficSeriesPoint {
    pub bucket: String,
    pub requests: i64,
    pub cost_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficReport {
    pub totals: TrafficTotals,
    pub breakdown: Vec<TrafficBreakdown>,
    pub series: Vec<TrafficSeriesPoint>,
}

/// A single activity log row (for current session activity feeds).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: Option<i64>,
    pub timestamp: String,
    pub session_id: String,
    pub event_type: String,
    pub title: String,
    pub detail: Option<String>,
    pub metadata_json: Option<String>,
}

/// Optional filters when querying activity entries.
#[derive(Clone, Debug, Default)]
pub struct ActivityFilter {
    pub session_id: Option<String>,
    pub event_type: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub query: Option<String>,
}

/// NVIDIA skill metadata and its global installation state. Catalog rows are
/// small; the skill files themselves are installed lazily by the skills CLI.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SkillRecord {
    pub name: String,
    pub path: String,
    pub description: String,
    pub product: String,
    pub category: String,
    pub subdomain: String,
    pub audience: String,
    pub activity_tags: String,
    pub enabled: bool,
    pub available: bool,
    pub catalog_updated_at: String,
    pub installed_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn db_path() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".skyport")
        .join("skyport.db")
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Open (or create) the SQLite database and ensure tables exist.
pub fn init_db() -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        crate::vault::ensure_secure_directory(parent)?;
    }
    crate::vault::reject_symlink(&path)?;
    let encrypted_database_exists = database_is_encrypted(&path)?;
    let key = load_or_create_database_key(encrypted_database_exists)?;
    init_db_at(&path, &key)
}

fn init_db_at(path: &Path, key: &[u8]) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    if database_is_plaintext(path)? {
        migrate_plaintext_database(path, key)?;
    }

    let conn = open_encrypted_database(path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    conn.execute_batch(
        "PRAGMA secure_delete = ON;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS request_log (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT    NOT NULL,
            provider          TEXT    NOT NULL,
            key_alias         TEXT    NOT NULL,
            model             TEXT    NOT NULL,
            status            INTEGER NOT NULL,
            latency_ms        INTEGER NOT NULL,
            prompt_tokens     INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            est_cost_usd      REAL    NOT NULL
        );

         CREATE TABLE IF NOT EXISTS budget_usage (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            provider        TEXT    NOT NULL,
            key_alias       TEXT    NOT NULL,
            period          TEXT    NOT NULL,
            total_cost_usd  REAL    NOT NULL DEFAULT 0.0,
            UNIQUE(provider, key_alias, period)
        );

         CREATE TABLE IF NOT EXISTS activity_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            session_id      TEXT    NOT NULL,
            event_type      TEXT    NOT NULL,
            title           TEXT    NOT NULL,
            detail          TEXT,
             metadata_json   TEXT
         );

         CREATE TABLE IF NOT EXISTS nvidia_skill (
             name               TEXT PRIMARY KEY,
             path               TEXT NOT NULL,
             description        TEXT NOT NULL,
             product            TEXT NOT NULL,
             category           TEXT NOT NULL,
             subdomain          TEXT NOT NULL,
             audience           TEXT NOT NULL,
             activity_tags      TEXT NOT NULL,
             enabled            INTEGER NOT NULL DEFAULT 0,
             available          INTEGER NOT NULL DEFAULT 1,
             catalog_updated_at TEXT NOT NULL,
             installed_at       TEXT
         );

        CREATE INDEX IF NOT EXISTS idx_request_log_timestamp ON request_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_request_log_provider_timestamp ON request_log(provider, timestamp);
        CREATE INDEX IF NOT EXISTS idx_request_log_model_timestamp ON request_log(model, timestamp);
        CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp);
         CREATE INDEX IF NOT EXISTS idx_activity_log_session ON activity_log(session_id, timestamp);
         CREATE INDEX IF NOT EXISTS idx_activity_log_type ON activity_log(event_type, timestamp);
         CREATE INDEX IF NOT EXISTS idx_nvidia_skill_category ON nvidia_skill(category);
         CREATE INDEX IF NOT EXISTS idx_nvidia_skill_product ON nvidia_skill(product);",
    )?;

    Ok(conn)
}

// ---------------------------------------------------------------------------
// Global skills catalog
// ---------------------------------------------------------------------------

fn skill_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SkillRecord> {
    Ok(SkillRecord {
        name: row.get(0)?,
        path: row.get(1)?,
        description: row.get(2)?,
        product: row.get(3)?,
        category: row.get(4)?,
        subdomain: row.get(5)?,
        audience: row.get(6)?,
        activity_tags: row.get(7)?,
        enabled: row.get(8)?,
        available: row.get(9)?,
        catalog_updated_at: row.get(10)?,
        installed_at: row.get(11)?,
    })
}

pub fn list_skills(
    conn: &rusqlite::Connection,
) -> Result<Vec<SkillRecord>, Box<dyn std::error::Error>> {
    let mut statement = conn.prepare(
        "SELECT name, path, description, product, category, subdomain, audience,
                activity_tags, enabled, available, catalog_updated_at, installed_at
         FROM nvidia_skill
         WHERE available = 1 OR enabled = 1 OR installed_at IS NOT NULL
         ORDER BY name",
    )?;
    let rows = statement.query_map([], skill_from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_skill(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Option<SkillRecord>, Box<dyn std::error::Error>> {
    let mut statement = conn.prepare(
        "SELECT name, path, description, product, category, subdomain, audience,
                activity_tags, enabled, available, catalog_updated_at, installed_at
         FROM nvidia_skill WHERE name = ?1",
    )?;
    let result = statement.query_row(params![name], skill_from_row);
    match result {
        Ok(skill) => Ok(Some(skill)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Replace remote metadata atomically while retaining local installation
/// state and custom imported skills. Removed upstream skills remain visible only while still installed.
pub fn upsert_skill_catalog(
    conn: &mut rusqlite::Connection,
    skills: &[SkillRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let transaction = conn.transaction()?;
    transaction.execute(
        "UPDATE nvidia_skill SET available = 0 WHERE subdomain != 'custom'",
        [],
    )?;
    {
        let mut statement = transaction.prepare(
            "INSERT INTO nvidia_skill (
                name, path, description, product, category, subdomain, audience,
                activity_tags, available, catalog_updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
             ON CONFLICT(name) DO UPDATE SET
                path = excluded.path,
                description = excluded.description,
                product = excluded.product,
                category = excluded.category,
                subdomain = excluded.subdomain,
                audience = excluded.audience,
                activity_tags = excluded.activity_tags,
                available = 1,
                catalog_updated_at = excluded.catalog_updated_at",
        )?;
        for skill in skills {
            statement.execute(params![
                skill.name,
                skill.path,
                skill.description,
                skill.product,
                skill.category,
                skill.subdomain,
                skill.audience,
                skill.activity_tags,
                skill.catalog_updated_at,
            ])?;
        }
    }
    transaction.execute(
        "DELETE FROM nvidia_skill WHERE available = 0 AND enabled = 0 AND installed_at IS NULL AND subdomain != 'custom'",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn insert_custom_skill(
    conn: &rusqlite::Connection,
    skill: &SkillRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT INTO nvidia_skill (
            name, path, description, product, category, subdomain, audience,
            activity_tags, enabled, available, catalog_updated_at, installed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(name) DO UPDATE SET
            path = excluded.path,
            description = excluded.description,
            product = excluded.product,
            category = excluded.category,
            subdomain = excluded.subdomain,
            audience = excluded.audience,
            activity_tags = excluded.activity_tags,
            enabled = excluded.enabled,
            available = excluded.available,
            catalog_updated_at = excluded.catalog_updated_at,
            installed_at = excluded.installed_at",
        params![
            skill.name,
            skill.path,
            skill.description,
            skill.product,
            skill.category,
            skill.subdomain,
            skill.audience,
            skill.activity_tags,
            skill.enabled,
            skill.available,
            skill.catalog_updated_at,
            skill.installed_at,
        ],
    )?;
    Ok(())
}

pub fn delete_skill(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let changed = conn.execute("DELETE FROM nvidia_skill WHERE name = ?1", params![name])?;
    Ok(changed == 1)
}

pub fn uninstall_skill(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let changed = conn.execute(
        "UPDATE nvidia_skill
         SET enabled = 0, installed_at = NULL
         WHERE name = ?1 AND subdomain != 'custom'",
        params![name],
    )?;
    if changed == 1 {
        let _ = conn.execute(
            "DELETE FROM nvidia_skill WHERE name = ?1 AND available = 0 AND subdomain != 'custom'",
            params![name],
        );
        return Ok(true);
    }
    delete_skill(conn, name)
}

pub fn set_skill_enabled(
    conn: &rusqlite::Connection,
    name: &str,
    enabled: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let now = Utc::now().to_rfc3339();
    let changed = if enabled {
        conn.execute(
            "UPDATE nvidia_skill
             SET enabled = 1, installed_at = COALESCE(installed_at, ?2)
             WHERE name = ?1 AND (available = 1 OR installed_at IS NOT NULL)",
            params![name, now],
        )?
    } else {
        conn.execute(
            "UPDATE nvidia_skill
             SET enabled = 0
             WHERE name = ?1",
            params![name],
        )?
    };
    Ok(changed == 1)
}

fn database_is_plaintext(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(format!("Telemetry database path is not a file: {}", path.display()).into());
    }
    let mut header = [0_u8; SQLITE_HEADER.len()];
    let read = file.read(&mut header)?;
    Ok(read == SQLITE_HEADER.len() && &header == SQLITE_HEADER)
}

fn database_is_encrypted(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            Err(format!("Telemetry database path is not a file: {}", path.display()).into())
        }
        Ok(metadata) => Ok(metadata.len() > 0 && !database_is_plaintext(path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn load_or_create_database_key(
    encrypted_database_exists: bool,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    match crate::credential_store::read(TELEMETRY_KEYRING_ACCOUNT)
        .map_err(|_| "Failed to access telemetry database credential store")?
    {
        Some(password) => {
            let mut key = Zeroizing::new(Vec::with_capacity(32));
            let decoded = BASE64.decode_vec(password.as_bytes(), &mut key);
            if decoded.is_err() || key.len() != 32 {
                return Err("Telemetry database key in credential store is invalid".into());
            }
            Ok(key)
        }
        None if encrypted_database_exists => {
            Err("Telemetry database key is missing from the credential store".into())
        }
        None => {
            use rand::RngCore;
            let mut key = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut key);
            let encoded = Zeroizing::new(BASE64.encode(key.as_slice()));
            crate::credential_store::write(TELEMETRY_KEYRING_ACCOUNT, encoded.as_str())
                .map_err(|_| "Failed to store telemetry database key in credential store")?;
            Ok(key)
        }
    }
}

fn apply_database_key(
    conn: &rusqlite::Connection,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            conn.handle(),
            key.as_ptr().cast(),
            i32::try_from(key.len()).map_err(|_| "Telemetry database key is too large")?,
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err("Failed to apply telemetry database encryption key".into());
    }
    Ok(())
}

fn verify_sqlcipher(conn: &rusqlite::Connection) -> Result<(), Box<dyn std::error::Error>> {
    let version = conn.query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0));
    if version.is_err() {
        return Err(
            "SQLCipher support is unavailable; refusing plaintext telemetry storage".into(),
        );
    }
    Ok(())
}

fn open_encrypted_database(
    path: &Path,
    key: &[u8],
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(path)?;
    apply_database_key(&conn, key)?;
    verify_sqlcipher(&conn)?;
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| "Telemetry database could not be decrypted".to_string())?;
    Ok(conn)
}

fn migrate_plaintext_database(path: &Path, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .ok_or("Telemetry database path has no parent")?;
    let encrypted_path = parent.join(format!(".skyport-{}.encrypted", uuid::Uuid::new_v4()));
    crate::vault::reject_symlink(&encrypted_path)?;

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let conn = rusqlite::Connection::open(path)?;
        verify_sqlcipher(&conn)?;
        let encrypted_path_text = encrypted_path
            .to_str()
            .ok_or("Telemetry database path is not valid UTF-8")?;
        conn.execute(
            "ATTACH DATABASE ?1 AS encrypted KEY ?2",
            params![encrypted_path_text, key],
        )?;
        conn.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))?;
        conn.execute_batch("DETACH DATABASE encrypted;")?;
        let checkpoint_busy: i64 =
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if checkpoint_busy != 0 {
            return Err("Telemetry database is in use; stop Skyport before migrating it".into());
        }
        drop(conn);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&encrypted_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let encrypted = open_encrypted_database(&encrypted_path, key)?;
        let mut integrity_check = encrypted.prepare("PRAGMA cipher_integrity_check")?;
        let mut integrity_errors = integrity_check.query([])?;
        if integrity_errors.next()?.is_some() {
            return Err("Encrypted telemetry database failed its integrity check".into());
        }
        drop(integrity_errors);
        drop(integrity_check);
        drop(encrypted);

        remove_plaintext_sidecars(path)?;
        crate::vault::atomic_replace(&encrypted_path, path)?;
        tracing::info!("migrated plaintext telemetry database to SQLCipher");
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = remove_plaintext_sidecars(&encrypted_path);
    }
    result
}

fn remove_plaintext_sidecars(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path_text = path
        .to_str()
        .ok_or("Telemetry database path is not valid UTF-8")?;
    for suffix in ["-journal", "-wal", "-shm"] {
        wipe_and_remove(&PathBuf::from(format!("{path_text}{suffix}")))?;
    }
    Ok(())
}

fn wipe_and_remove(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    crate::vault::reject_symlink(path)?;
    let length = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => {
            return Err(format!("SQLite sidecar path is not a file: {}", path.display()).into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut file = OpenOptions::new().write(true).open(path)?;
    let zeros = [0_u8; 8192];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(zeros.len() as u64))?;
        file.write_all(&zeros[..count])?;
        remaining -= count as u64;
    }
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Insert a new request log entry.
pub fn log_request(
    conn: &rusqlite::Connection,
    entry: &RequestLogEntry,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT INTO request_log
            (timestamp, provider, key_alias, model, status,
             latency_ms, prompt_tokens, completion_tokens, est_cost_usd)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            entry.timestamp,
            entry.provider,
            entry.key_alias,
            entry.model,
            entry.status,
            entry.latency_ms,
            entry.prompt_tokens,
            entry.completion_tokens,
            entry.est_cost_usd,
        ],
    )?;
    Ok(())
}

/// Fetch recent log entries (most recent first).
pub fn get_logs(
    conn: &rusqlite::Connection,
    limit: i64,
    offset: i64,
) -> Result<Vec<RequestLogEntry>, Box<dyn std::error::Error>> {
    let stmt = conn.prepare(
        "SELECT id, timestamp, provider, key_alias, model, status,
                latency_ms, prompt_tokens, completion_tokens, est_cost_usd
         FROM request_log
         ORDER BY id DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    read_log_entries(stmt, params![limit, offset])
}

/// Fetch log entries recorded at or after a Unix epoch-millisecond timestamp
/// (most recent first). Used by the dashboard for per-session aggregation.
pub fn get_logs_since(
    conn: &rusqlite::Connection,
    since_ms: i64,
    limit: i64,
) -> Result<Vec<RequestLogEntry>, Box<dyn std::error::Error>> {
    let since = chrono::DateTime::from_timestamp_millis(since_ms)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    let stmt = conn.prepare(
        "SELECT id, timestamp, provider, key_alias, model, status,
                latency_ms, prompt_tokens, completion_tokens, est_cost_usd
         FROM request_log
         WHERE timestamp >= ?1
         ORDER BY id DESC
         LIMIT ?2",
    )?;
    read_log_entries(stmt, params![since, limit])
}

/// Query telemetry with optional filters and return the total matching rows for
/// stable server-side pagination.
pub fn query_logs(
    conn: &rusqlite::Connection,
    filter: &LogFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<RequestLogEntry>, i64), Box<dyn std::error::Error>> {
    let (where_clause, values) = filter_sql(filter)?;
    let count_sql = format!("SELECT COUNT(*) FROM request_log{where_clause}");
    let total = conn.query_row(&count_sql, params_from_iter(values.iter()), |row| {
        row.get(0)
    })?;
    let sql = format!(
        "SELECT id, timestamp, provider, key_alias, model, status, \
                latency_ms, prompt_tokens, completion_tokens, est_cost_usd \
         FROM request_log{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    let mut values = values;
    values.push(SqlValue::Integer(limit.clamp(1, 500)));
    values.push(SqlValue::Integer(offset.max(0)));
    let stmt = conn.prepare(&sql)?;
    let logs = read_log_entries(stmt, params_from_iter(values.iter()))?;
    Ok((logs, total))
}

/// Return totals, a selected breakdown, and a time series for filtered traffic.
pub fn traffic_report(
    conn: &rusqlite::Connection,
    filter: &LogFilter,
    group_by: &str,
) -> Result<TrafficReport, Box<dyn std::error::Error>> {
    let group_column = match group_by {
        "provider" => "provider",
        "model" => "model",
        "key" => "key_alias",
        "status" => "CAST(status AS TEXT)",
        "hour" => "strftime('%Y-%m-%dT%H:00Z', timestamp)",
        _ => return Err(format!("Invalid group_by: {group_by}").into()),
    };
    let (where_clause, values) = filter_sql(filter)?;
    let totals_sql = format!(
        "SELECT COUNT(*), COALESCE(SUM(prompt_tokens + completion_tokens), 0), \
                COALESCE(SUM(est_cost_usd), 0.0), COALESCE(AVG(latency_ms), 0.0), \
                COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) \
         FROM request_log{where_clause}"
    );
    let totals = conn.query_row(&totals_sql, params_from_iter(values.iter()), |row| {
        Ok(TrafficTotals {
            total_requests: row.get(0)?,
            total_tokens: row.get(1)?,
            total_cost_usd: row.get(2)?,
            avg_latency_ms: row.get(3)?,
            error_count: row.get(4)?,
        })
    })?;
    let breakdown_sql = format!(
        "SELECT {group_column}, COUNT(*), \
                COALESCE(SUM(prompt_tokens + completion_tokens), 0), \
                COALESCE(SUM(est_cost_usd), 0.0), COALESCE(AVG(latency_ms), 0.0), \
                COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) \
         FROM request_log{where_clause} GROUP BY {group_column} \
         ORDER BY SUM(est_cost_usd) DESC, COUNT(*) DESC LIMIT 50"
    );
    let mut stmt = conn.prepare(&breakdown_sql)?;
    let breakdown = stmt
        .query_map(params_from_iter(values.iter()), |row| {
            Ok(TrafficBreakdown {
                group: row.get(0)?,
                requests: row.get(1)?,
                tokens: row.get(2)?,
                cost_usd: row.get(3)?,
                avg_latency_ms: row.get(4)?,
                error_count: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let now_ms = Utc::now().timestamp_millis();
    let start_ms = filter.from_ms.unwrap_or(now_ms - 24 * 60 * 60 * 1000);
    let bucket = if now_ms.saturating_sub(start_ms) <= 7 * 24 * 60 * 60 * 1000 {
        "strftime('%Y-%m-%dT%H:00Z', timestamp)"
    } else {
        "strftime('%Y-%m-%d', timestamp)"
    };
    let series_sql = format!(
        "SELECT {bucket}, COUNT(*), COALESCE(SUM(est_cost_usd), 0.0) \
         FROM request_log{where_clause} GROUP BY {bucket} ORDER BY {bucket} ASC"
    );
    let mut stmt = conn.prepare(&series_sql)?;
    let series = stmt
        .query_map(params_from_iter(values.iter()), |row| {
            Ok(TrafficSeriesPoint {
                bucket: row.get(0)?,
                requests: row.get(1)?,
                cost_usd: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TrafficReport {
        totals,
        breakdown,
        series,
    })
}

/// Remove telemetry older than the configured retention window.
pub fn prune_logs(
    conn: &rusqlite::Connection,
    retention_days: u32,
) -> Result<usize, Box<dyn std::error::Error>> {
    let cutoff = (Utc::now() - chrono::Duration::days(i64::from(retention_days))).to_rfc3339();
    let request_rows = conn.execute(
        "DELETE FROM request_log WHERE timestamp < ?1",
        params![cutoff],
    )?;
    let cutoff_day = (Utc::now() - chrono::Duration::days(i64::from(retention_days)))
        .format("%Y-%m-%d")
        .to_string();
    let cutoff_month = cutoff_day[..7].to_string();
    let budget_rows = conn.execute(
        "DELETE FROM budget_usage
         WHERE (length(period) = 10 AND period < ?1)
            OR (length(period) = 7 AND period < ?2)",
        params![cutoff_day, cutoff_month],
    )?;
    let activity_rows = conn.execute(
        "DELETE FROM activity_log WHERE timestamp < ?1",
        params![cutoff],
    )?;
    Ok(request_rows + budget_rows + activity_rows)
}

// ---------------------------------------------------------------------------
// Activity Logging & Querying
// ---------------------------------------------------------------------------

/// Insert a new activity log entry and return its assigned row ID.
pub fn log_activity(
    conn: &rusqlite::Connection,
    entry: &ActivityEntry,
) -> Result<i64, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT INTO activity_log
            (timestamp, session_id, event_type, title, detail, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            entry.timestamp,
            entry.session_id,
            entry.event_type,
            entry.title,
            entry.detail,
            entry.metadata_json,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Fetch activities matching optional filter constraints, newest first.
pub fn query_activities(
    conn: &rusqlite::Connection,
    filter: &ActivityFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ActivityEntry>, i64), Box<dyn std::error::Error>> {
    let mut clauses = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(session) = filter.session_id.as_deref().filter(|s| !s.is_empty()) {
        clauses.push("session_id = ?".to_string());
        values.push(SqlValue::Text(session.to_string()));
    }
    if let Some(etype) = filter.event_type.as_deref().filter(|s| !s.is_empty()) {
        clauses.push("event_type = ?".to_string());
        values.push(SqlValue::Text(etype.to_string()));
    }
    if let Some(ms) = filter.from_ms {
        clauses.push("timestamp >= ?".to_string());
        values.push(SqlValue::Text(timestamp_from_ms(ms)?));
    }
    if let Some(ms) = filter.to_ms {
        clauses.push("timestamp <= ?".to_string());
        values.push(SqlValue::Text(timestamp_from_ms(ms)?));
    }
    if let Some(q) = filter
        .query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        clauses.push("(title LIKE ? OR detail LIKE ?)".to_string());
        let pat = format!("%{q}%");
        values.push(SqlValue::Text(pat.clone()));
        values.push(SqlValue::Text(pat));
    }

    let where_clause = if clauses.empty_or_all_blank() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM activity_log{where_clause}");
    let total: i64 = conn.query_row(&count_sql, params_from_iter(values.iter()), |row| {
        row.get(0)
    })?;

    let sql = format!(
        "SELECT id, timestamp, session_id, event_type, title, detail, metadata_json \
         FROM activity_log{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    let mut values = values;
    values.push(SqlValue::Integer(limit.clamp(1, 1000)));
    values.push(SqlValue::Integer(offset.max(0)));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values.iter()), |row| {
        Ok(ActivityEntry {
            id: Some(row.get(0)?),
            timestamp: row.get(1)?,
            session_id: row.get(2)?,
            event_type: row.get(3)?,
            title: row.get(4)?,
            detail: row.get(5)?,
            metadata_json: row.get(6)?,
        })
    })?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok((entries, total))
}

trait EmptyOrBlank {
    fn empty_or_all_blank(&self) -> bool;
}

impl EmptyOrBlank for Vec<String> {
    fn empty_or_all_blank(&self) -> bool {
        self.is_empty()
    }
}

/// Delete activities for a specific session or clear all activities.
pub fn clear_activities(
    conn: &rusqlite::Connection,
    session_id: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let rows = if let Some(session) = session_id {
        conn.execute(
            "DELETE FROM activity_log WHERE session_id = ?1",
            params![session],
        )?
    } else {
        conn.execute("DELETE FROM activity_log", [])?
    };
    Ok(rows)
}

fn filter_sql(filter: &LogFilter) -> Result<(String, Vec<SqlValue>), Box<dyn std::error::Error>> {
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    {
        let mut text = |column: &str, value: &Option<String>| {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                clauses.push(format!("{column} = ?"));
                values.push(SqlValue::Text(value.to_string()));
            }
        };
        text("provider", &filter.provider);
        text("model", &filter.model);
        text("key_alias", &filter.key_alias);
    }
    if let Some(status) = filter.status.as_deref().filter(|value| !value.is_empty()) {
        match status {
            "ok" => clauses.push("status >= 200 AND status < 400".into()),
            "4xx" => clauses.push("status >= 400 AND status < 500".into()),
            "5xx" => clauses.push("status >= 500".into()),
            "errors" => clauses.push("status >= 400".into()),
            value => {
                let value: i64 = value
                    .parse()
                    .map_err(|_| format!("Invalid status: {status}"))?;
                clauses.push("status = ?".into());
                values.push(SqlValue::Integer(value));
            }
        }
    }
    number_clause(
        &mut clauses,
        &mut values,
        "est_cost_usd",
        ">=",
        filter.min_cost.map(SqlValue::Real),
    );
    number_clause(
        &mut clauses,
        &mut values,
        "est_cost_usd",
        "<=",
        filter.max_cost.map(SqlValue::Real),
    );
    number_clause(
        &mut clauses,
        &mut values,
        "latency_ms",
        ">=",
        filter.min_latency.map(SqlValue::Integer),
    );
    number_clause(
        &mut clauses,
        &mut values,
        "latency_ms",
        "<=",
        filter.max_latency.map(SqlValue::Integer),
    );
    number_clause(
        &mut clauses,
        &mut values,
        "prompt_tokens + completion_tokens",
        ">=",
        filter.min_tokens.map(SqlValue::Integer),
    );
    number_clause(
        &mut clauses,
        &mut values,
        "prompt_tokens + completion_tokens",
        "<=",
        filter.max_tokens.map(SqlValue::Integer),
    );
    if let Some(ms) = filter.from_ms {
        clauses.push("timestamp >= ?".into());
        values.push(SqlValue::Text(timestamp_from_ms(ms)?));
    }
    if let Some(ms) = filter.to_ms {
        clauses.push("timestamp <= ?".into());
        values.push(SqlValue::Text(timestamp_from_ms(ms)?));
    }
    if let Some(query) = filter
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        clauses.push("(provider LIKE ? OR model LIKE ? OR key_alias LIKE ?)".into());
        let pattern = format!("%{query}%");
        values.extend([
            SqlValue::Text(pattern.clone()),
            SqlValue::Text(pattern.clone()),
            SqlValue::Text(pattern),
        ]);
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    Ok((where_clause, values))
}

fn number_clause(
    clauses: &mut Vec<String>,
    values: &mut Vec<SqlValue>,
    column: &str,
    operator: &str,
    value: Option<SqlValue>,
) {
    if let Some(value) = value {
        clauses.push(format!("{column} {operator} ?"));
        values.push(value);
    }
}

fn timestamp_from_ms(ms: i64) -> Result<String, Box<dyn std::error::Error>> {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|timestamp| timestamp.to_rfc3339())
        .ok_or_else(|| format!("Invalid timestamp: {ms}").into())
}

fn read_log_entries<P: rusqlite::Params>(
    mut stmt: rusqlite::Statement<'_>,
    params: P,
) -> Result<Vec<RequestLogEntry>, Box<dyn std::error::Error>> {
    let rows = stmt.query_map(params, |row| {
        Ok(RequestLogEntry {
            id: Some(row.get(0)?),
            timestamp: row.get(1)?,
            provider: row.get(2)?,
            key_alias: row.get(3)?,
            model: row.get(4)?,
            status: row.get(5)?,
            latency_ms: row.get(6)?,
            prompt_tokens: row.get(7)?,
            completion_tokens: row.get(8)?,
            est_cost_usd: row.get(9)?,
        })
    })?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

/// Total estimated spend recorded today (local time).
pub fn get_today_cost(conn: &rusqlite::Connection) -> Result<f64, Box<dyn std::error::Error>> {
    let cost = conn.query_row(
        "SELECT COALESCE(SUM(est_cost_usd), 0.0)
         FROM request_log
         WHERE date(timestamp, 'localtime') = date('now', 'localtime')",
        [],
        |row| row.get(0),
    )?;
    Ok(cost)
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Compute aggregate stats for a time range ("24h", "7d", or "30d").
pub fn get_stats(
    conn: &rusqlite::Connection,
    range: &str,
) -> Result<RequestStats, Box<dyn std::error::Error>> {
    let hours: i64 = match range {
        "1h" => 1,
        "6h" => 6,
        "24h" => 24,
        "7d" => 7 * 24,
        "30d" => 30 * 24,
        "90d" => 90 * 24,
        _ => return Err(format!("Invalid range: {range}").into()),
    };

    let cutoff = (Utc::now() - chrono::Duration::hours(hours))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();

    // Overall aggregates
    let (total_requests, total_tokens, total_cost_usd, avg_latency_ms, error_count): (
        i64,
        i64,
        f64,
        f64,
        i64,
    ) = conn.query_row(
        "SELECT
            COUNT(*),
            COALESCE(SUM(prompt_tokens + completion_tokens), 0),
            COALESCE(SUM(est_cost_usd), 0.0),
            COALESCE(AVG(latency_ms), 0.0),
            COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0)
         FROM request_log
         WHERE timestamp >= ?1",
        params![cutoff],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;

    // Per-provider aggregates
    let mut stmt = conn.prepare(
        "SELECT
            provider,
            COUNT(*),
            COALESCE(SUM(prompt_tokens + completion_tokens), 0),
            COALESCE(SUM(est_cost_usd), 0.0),
            COALESCE(AVG(latency_ms), 0.0)
         FROM request_log
         WHERE timestamp >= ?1
         GROUP BY provider",
    )?;

    let mut by_provider = HashMap::new();
    let rows = stmt.query_map(params![cutoff], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ProviderStats {
                requests: row.get(1)?,
                tokens: row.get(2)?,
                cost_usd: row.get(3)?,
                avg_latency_ms: row.get(4)?,
            },
        ))
    })?;

    for row in rows {
        let (provider, stats) = row?;
        by_provider.insert(provider, stats);
    }

    // Per-model aggregates
    let mut stmt = conn.prepare(
        "SELECT
            model,
            COUNT(*),
            COALESCE(SUM(prompt_tokens + completion_tokens), 0),
            COALESCE(SUM(est_cost_usd), 0.0),
            COALESCE(AVG(latency_ms), 0.0)
         FROM request_log
         WHERE timestamp >= ?1
         GROUP BY model",
    )?;

    let mut by_model = HashMap::new();
    let rows = stmt.query_map(params![cutoff], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ProviderStats {
                requests: row.get(1)?,
                tokens: row.get(2)?,
                cost_usd: row.get(3)?,
                avg_latency_ms: row.get(4)?,
            },
        ))
    })?;

    for row in rows {
        let (model, stats) = row?;
        by_model.insert(model, stats);
    }

    Ok(RequestStats {
        total_requests,
        total_tokens,
        total_cost_usd,
        avg_latency_ms,
        error_count,
        by_provider,
        by_model,
    })
}

// ---------------------------------------------------------------------------
// Budget tracking
// ---------------------------------------------------------------------------

/// Get total cost for a provider in a given period (e.g. "2024-01" or "2024-01-15").
pub fn get_budget_usage(
    conn: &rusqlite::Connection,
    provider: &str,
    period: &str,
) -> Result<f64, Box<dyn std::error::Error>> {
    let total: f64 = conn.query_row(
        "SELECT COALESCE(SUM(total_cost_usd), 0.0)
         FROM budget_usage
         WHERE provider = ?1 AND period = ?2",
        params![provider, period],
        |row| row.get(0),
    )?;
    Ok(total)
}

fn get_scoped_budget_usage(
    conn: &rusqlite::Connection,
    provider: &str,
    key_alias: Option<&str>,
    period: &str,
) -> Result<f64, Box<dyn std::error::Error>> {
    let total = conn.query_row(
        "SELECT COALESCE(SUM(total_cost_usd), 0.0)
         FROM budget_usage
         WHERE provider = ?1 AND period = ?2
           AND (?3 IS NULL OR key_alias = ?3)",
        params![provider, period, key_alias],
        |row| row.get(0),
    )?;
    Ok(total)
}

/// Upsert cost into budget_usage for a (provider, key_alias, period) triple.
pub fn update_budget_usage(
    conn: &rusqlite::Connection,
    provider: &str,
    key_alias: &str,
    period: &str,
    cost: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT INTO budget_usage (provider, key_alias, period, total_cost_usd)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(provider, key_alias, period)
         DO UPDATE SET total_cost_usd = total_cost_usd + ?5",
        params![provider, key_alias, period, cost, cost],
    )?;
    Ok(())
}

/// Check whether a request is within the configured budget caps.
/// Returns `true` if spending is still within limits, `false` if over cap.
pub fn check_budget(
    conn: &rusqlite::Connection,
    provider: &str,
    key_alias: Option<&str>,
    budget_config: &crate::config::BudgetConfig,
    projected_cost: f64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Monthly cap
    if let Some(monthly_cap) = budget_config.monthly_cap_usd {
        let period = Utc::now().format("%Y-%m").to_string();
        let usage = get_scoped_budget_usage(conn, provider, key_alias, &period)?;
        if usage + projected_cost > monthly_cap {
            return Ok(false);
        }
    }

    // Daily cap
    if let Some(daily_cap) = budget_config.daily_cap_usd {
        let period = Utc::now().format("%Y-%m-%d").to_string();
        let usage = get_scoped_budget_usage(conn, provider, key_alias, &period)?;
        if usage + projected_cost > daily_cap {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BudgetConfig;

    fn telemetry_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                provider TEXT NOT NULL, key_alias TEXT NOT NULL, model TEXT NOT NULL,
                status INTEGER NOT NULL, latency_ms INTEGER NOT NULL,
                prompt_tokens INTEGER NOT NULL, completion_tokens INTEGER NOT NULL,
                est_cost_usd REAL NOT NULL
            );
            CREATE TABLE budget_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL,
                key_alias TEXT NOT NULL, period TEXT NOT NULL,
                total_cost_usd REAL NOT NULL DEFAULT 0.0,
                UNIQUE(provider, key_alias, period)
            );
            CREATE TABLE activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                metadata_json TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn skill_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE nvidia_skill (
                name TEXT PRIMARY KEY, path TEXT NOT NULL, description TEXT NOT NULL,
                product TEXT NOT NULL, category TEXT NOT NULL, subdomain TEXT NOT NULL,
                audience TEXT NOT NULL, activity_tags TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0, available INTEGER NOT NULL DEFAULT 1,
                catalog_updated_at TEXT NOT NULL, installed_at TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn skill(name: &str, fetched_at: &str) -> SkillRecord {
        SkillRecord {
            name: name.to_string(),
            path: format!("skills/{name}"),
            description: format!("Description for {name}"),
            product: "Test product".into(),
            category: "developer_tools".into(),
            subdomain: "agentic-ai".into(),
            audience: "developer".into(),
            activity_tags: "test,validate".into(),
            enabled: false,
            available: true,
            catalog_updated_at: fetched_at.to_string(),
            installed_at: None,
        }
    }

    fn entry(provider: &str, model: &str, status: i32, cost: f64) -> RequestLogEntry {
        RequestLogEntry {
            id: None,
            timestamp: "2026-08-17T12:00:00Z".into(),
            provider: provider.into(),
            key_alias: format!("{provider}-key"),
            model: model.into(),
            status,
            latency_ms: 250,
            prompt_tokens: 100,
            completion_tokens: 40,
            est_cost_usd: cost,
        }
    }

    #[test]
    fn monthly_budget_blocks_at_cap() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE budget_usage (provider TEXT NOT NULL, key_alias TEXT NOT NULL, period TEXT NOT NULL, total_cost_usd REAL NOT NULL DEFAULT 0.0, UNIQUE(provider, key_alias, period));").unwrap();
        let period = Utc::now().format("%Y-%m").to_string();
        update_budget_usage(&conn, "openai", "key-a", &period, 5.0).unwrap();
        let budget = BudgetConfig {
            monthly_cap_usd: Some(5.0),
            daily_cap_usd: None,
            max_rpm: None,
        };
        assert!(!check_budget(&conn, "openai", Some("key-a"), &budget, 0.01).unwrap());
    }

    #[test]
    fn skill_catalog_refresh_preserves_enabled_state() {
        let mut conn = skill_db();
        upsert_skill_catalog(&mut conn, &[skill("first-skill", "first")]).unwrap();
        assert!(set_skill_enabled(&conn, "first-skill", true).unwrap());

        let mut updated = skill("first-skill", "second");
        updated.description = "Updated upstream description".into();
        upsert_skill_catalog(&mut conn, &[updated]).unwrap();

        let stored = get_skill(&conn, "first-skill").unwrap().unwrap();
        assert!(stored.enabled);
        assert!(stored.installed_at.is_some());
        assert_eq!(stored.description, "Updated upstream description");
    }

    #[test]
    fn skill_catalog_keeps_only_installed_removed_skills() {
        let mut conn = skill_db();
        upsert_skill_catalog(
            &mut conn,
            &[
                skill("installed-skill", "first"),
                skill("unused-skill", "first"),
            ],
        )
        .unwrap();
        set_skill_enabled(&conn, "installed-skill", true).unwrap();

        upsert_skill_catalog(&mut conn, &[skill("current-skill", "second")]).unwrap();

        assert!(get_skill(&conn, "unused-skill").unwrap().is_none());
        let removed = get_skill(&conn, "installed-skill").unwrap().unwrap();
        assert!(removed.enabled);
        assert!(!removed.available);
        assert_eq!(list_skills(&conn).unwrap().len(), 2);
    }

    #[test]
    fn skill_deactivation_preserves_downloaded_installed_at() {
        let mut conn = skill_db();
        upsert_skill_catalog(&mut conn, &[skill("cached-skill", "first")]).unwrap();
        assert!(set_skill_enabled(&conn, "cached-skill", true).unwrap());

        let initial = get_skill(&conn, "cached-skill").unwrap().unwrap();
        assert!(initial.enabled);
        assert!(initial.installed_at.is_some());
        let initial_installed_at = initial.installed_at.clone();

        // Deactivate skill (remove from active context)
        assert!(set_skill_enabled(&conn, "cached-skill", false).unwrap());

        let deactivated = get_skill(&conn, "cached-skill").unwrap().unwrap();
        assert!(!deactivated.enabled);
        assert_eq!(deactivated.installed_at, initial_installed_at);

        // Deactivated skill must still appear in list_skills as downloaded on device
        let list = list_skills(&conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "cached-skill");
        assert!(!list[0].enabled);
        assert!(list[0].installed_at.is_some());

        // Re-enabling retains original installed_at
        assert!(set_skill_enabled(&conn, "cached-skill", true).unwrap());
        let reactivated = get_skill(&conn, "cached-skill").unwrap().unwrap();
        assert!(reactivated.enabled);
        assert_eq!(reactivated.installed_at, initial_installed_at);

        // Explicit uninstall removes downloaded state
        assert!(uninstall_skill(&conn, "cached-skill").unwrap());
        let uninstalled = get_skill(&conn, "cached-skill").unwrap().unwrap();
        assert!(!uninstalled.enabled);
        assert!(uninstalled.installed_at.is_none());
    }

    #[test]
    fn unknown_skill_cannot_be_enabled() {
        let conn = skill_db();
        assert!(!set_skill_enabled(&conn, "missing", true).unwrap());
    }

    #[test]
    fn custom_skills_persist_across_catalog_refresh() {
        let mut conn = skill_db();
        let custom = SkillRecord {
            name: "custom-analyzer".into(),
            path: "custom/my-org/analyzer".into(),
            description: "Custom internal skill".into(),
            product: "Custom Skills".into(),
            category: "developer_tools".into(),
            subdomain: "custom".into(),
            audience: "developer".into(),
            activity_tags: "custom,imported".into(),
            enabled: true,
            available: true,
            catalog_updated_at: "2026-08-19T00:00:00Z".into(),
            installed_at: Some("2026-08-19T00:00:00Z".into()),
        };
        insert_custom_skill(&conn, &custom).unwrap();
        assert_eq!(
            get_skill(&conn, "custom-analyzer").unwrap().unwrap().name,
            "custom-analyzer"
        );

        // Refresh remote catalog with standard skills
        upsert_skill_catalog(&mut conn, &[skill("nvidia-official", "first")]).unwrap();

        // Custom skill must remain intact and available
        let preserved = get_skill(&conn, "custom-analyzer").unwrap().unwrap();
        assert_eq!(preserved.name, "custom-analyzer");
        assert!(preserved.available);
        assert!(preserved.enabled);
        assert_eq!(list_skills(&conn).unwrap().len(), 2);

        // Delete custom skill
        assert!(delete_skill(&conn, "custom-analyzer").unwrap());
        assert!(get_skill(&conn, "custom-analyzer").unwrap().is_none());
    }

    #[test]
    fn filtered_logs_return_only_matching_rows_and_total() {
        let conn = telemetry_db();
        log_request(&conn, &entry("openai", "gpt-5", 200, 0.03)).unwrap();
        log_request(&conn, &entry("groq", "llama", 429, 0.0)).unwrap();
        let filter = LogFilter {
            provider: Some("openai".into()),
            min_cost: Some(0.01),
            ..Default::default()
        };
        let (logs, total) = query_logs(&conn, &filter, 50, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(logs[0].model, "gpt-5");
    }

    #[test]
    fn traffic_report_groups_errors_and_cost() {
        let conn = telemetry_db();
        log_request(&conn, &entry("openai", "gpt-5", 200, 0.03)).unwrap();
        log_request(&conn, &entry("groq", "llama", 502, 0.0)).unwrap();
        let report = traffic_report(&conn, &LogFilter::default(), "provider").unwrap();
        assert_eq!(report.totals.total_requests, 2);
        assert_eq!(report.totals.error_count, 1);
        assert_eq!(report.breakdown.len(), 2);
        assert_eq!(report.series.len(), 1);
    }

    #[test]
    fn prune_logs_removes_expired_entries() {
        let conn = telemetry_db();
        let mut old = entry("openai", "gpt-5", 200, 0.03);
        old.timestamp = "2000-01-01T00:00:00Z".into();
        log_request(&conn, &old).unwrap();
        assert_eq!(prune_logs(&conn, 90).unwrap(), 1);
    }

    #[test]
    fn activity_log_records_and_queries_with_filters() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE activity_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                session_id      TEXT    NOT NULL,
                event_type      TEXT    NOT NULL,
                title           TEXT    NOT NULL,
                detail          TEXT,
                metadata_json   TEXT
            );",
        )
        .unwrap();

        let id1 = log_activity(
            &conn,
            &ActivityEntry {
                id: None,
                timestamp: "2026-08-18T19:01:42Z".into(),
                session_id: "sess-1".into(),
                event_type: "read".into(),
                title: "Read src/router.ts".into(),
                detail: Some("Lines 1-299".into()),
                metadata_json: None,
            },
        )
        .unwrap();
        assert!(id1 > 0);

        log_activity(
            &conn,
            &ActivityEntry {
                id: None,
                timestamp: "2026-08-18T19:01:45Z".into(),
                session_id: "sess-1".into(),
                event_type: "llm_call".into(),
                title: "→ Kimi".into(),
                detail: Some("moonshot-v1-8k · 2.4k tok · 320ms".into()),
                metadata_json: None,
            },
        )
        .unwrap();

        log_activity(
            &conn,
            &ActivityEntry {
                id: None,
                timestamp: "2026-08-18T19:01:49Z".into(),
                session_id: "sess-1".into(),
                event_type: "modify".into(),
                title: "Modified router.ts".into(),
                detail: Some("+12 -3 lines".into()),
                metadata_json: None,
            },
        )
        .unwrap();

        let (all, total) = query_activities(&conn, &ActivityFilter::default(), 10, 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].title, "Modified router.ts"); // newest first

        let filter = ActivityFilter {
            event_type: Some("read".into()),
            ..Default::default()
        };
        let (reads, total_reads) = query_activities(&conn, &filter, 10, 0).unwrap();
        assert_eq!(total_reads, 1);
        assert_eq!(reads[0].title, "Read src/router.ts");

        let search = ActivityFilter {
            query: Some("Kimi".into()),
            ..Default::default()
        };
        let (results, total_kimi) = query_activities(&conn, &search, 10, 0).unwrap();
        assert_eq!(total_kimi, 1);
        assert_eq!(results[0].title, "→ Kimi");

        let deleted = clear_activities(&conn, Some("sess-1")).unwrap();
        assert_eq!(deleted, 3);
        let (empty, total_after) =
            query_activities(&conn, &ActivityFilter::default(), 10, 0).unwrap();
        assert_eq!(total_after, 0);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn new_database_is_encrypted_at_rest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("telemetry.db");
        let key = [7_u8; 32];

        let conn = init_db_at(&path, &key).unwrap();
        log_request(&conn, &entry("openai", "gpt-5", 200, 0.03)).unwrap();
        drop(conn);

        let bytes = std::fs::read(&path).unwrap();
        assert_ne!(&bytes[..SQLITE_HEADER.len()], SQLITE_HEADER);
        let plaintext = rusqlite::Connection::open(&path).unwrap();
        assert!(plaintext
            .query_row("SELECT count(*) FROM request_log", [], |row| row
                .get::<_, i64>(0))
            .is_err());
        drop(plaintext);

        let encrypted = open_encrypted_database(&path, &key).unwrap();
        assert_eq!(get_logs(&encrypted, 10, 0).unwrap().len(), 1);
    }

    #[test]
    fn plaintext_database_is_migrated_without_losing_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("telemetry.db");
        let plaintext = rusqlite::Connection::open(&path).unwrap();
        plaintext
            .execute_batch(
                "CREATE TABLE preserved (value TEXT NOT NULL);
                 INSERT INTO preserved VALUES ('existing telemetry');",
            )
            .unwrap();
        drop(plaintext);
        assert!(database_is_plaintext(&path).unwrap());

        let key = [11_u8; 32];
        let encrypted = init_db_at(&path, &key).unwrap();
        let value: String = encrypted
            .query_row("SELECT value FROM preserved", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "existing telemetry");
        drop(encrypted);

        assert!(!database_is_plaintext(&path).unwrap());
        assert!(open_encrypted_database(&path, &[12_u8; 32]).is_err());
        assert!(open_encrypted_database(&path, &key).is_ok());
    }
}
