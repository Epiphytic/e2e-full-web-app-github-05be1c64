# SQLite Web Editor - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust web application with htmx frontend that lets users authenticate via JWT and interactively edit SQLite databases (create/drop tables, add/remove columns, browse/edit data).

**Architecture:** Actix-web serves both the API and HTML templates. Authentication uses a local JWT CA (RSA key pair) with a `.well-known/jwks.json` endpoint. The frontend is server-rendered HTML enhanced with htmx for dynamic interactions. SQLite is the data store, accessed via `rusqlite`. Playwright handles E2E testing with JWT-based auth setup.

**Tech Stack:** Rust (actix-web, rusqlite, jsonwebtoken, askama), htmx 2.0.8, Playwright 1.58.1+ (TypeScript), GitHub Actions (super-linter, dependency-review-action)

---

## Overview

The application is structured in layers:

1. **JWT Infrastructure** - Local RSA key pair generation, JWT signing/verification, JWKS `.well-known` endpoint
2. **Backend API** - Actix-web routes for table management (CREATE/DROP), schema modification (ALTER TABLE), and data operations (SELECT/INSERT/UPDATE/DELETE)
3. **Frontend** - Askama HTML templates with htmx attributes for dynamic table/column/data editing without full page reloads
4. **E2E Tests** - Playwright tests covering auth flow, table CRUD, and schema modification
5. **CI/CD** - GitHub Actions for linting and dependency review on PRs

### Directory Structure

```
.
├── .github/
│   └── workflows/
│       ├── lint.yml
│       └── dependency-review.yml
├── certs/                    # Generated at build/dev time, gitignored
│   ├── private_key.pem
│   └── public_key.pem
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs            # JWT creation/validation
│   │   ├── jwks.rs           # .well-known/jwks.json endpoint
│   │   └── middleware.rs     # Auth middleware
│   ├── db/
│   │   ├── mod.rs
│   │   ├── connection.rs     # SQLite connection pool
│   │   ├── tables.rs         # Table CRUD operations
│   │   └── schema.rs         # Column/schema operations
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── auth.rs           # Login/logout routes
│   │   ├── tables.rs         # Table management routes
│   │   ├── schema.rs         # Schema modification routes
│   │   └── well_known.rs     # .well-known endpoint
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── table_list.html
│       ├── table_detail.html
│       ├── partials/
│       │   ├── table_row.html
│       │   ├── column_form.html
│       │   └── alert.html
├── tests/
│   └── e2e/
│       ├── playwright.config.ts
│       ├── package.json
│       ├── auth.setup.ts
│       ├── auth.spec.ts
│       ├── tables.spec.ts
│       └── schema.spec.ts
├── Cargo.toml
├── .gitignore
└── README.md
```

## Risk Areas

1. **SQLite ALTER TABLE limitations** - SQLite only supports `ADD COLUMN` natively. Removing columns requires creating a new table, copying data, dropping old, and renaming. This is complex and error-prone.
2. **JWT key management in CI** - E2E tests need access to the JWT private key to mint tokens. Key generation must be deterministic or happen as part of test setup.
3. **Concurrent SQLite access** - SQLite has limited write concurrency. Need WAL mode and proper connection pooling via `r2d2-sqlite` or similar.
4. **htmx error handling** - Server errors need to return proper HTML fragments for htmx to swap, not raw error codes.
5. **Playwright test flakiness** - Dynamic htmx swaps may need explicit waits in tests to avoid race conditions.
6. **Super-linter configuration** - Need to configure which linters run (rustfmt, clippy for Rust; eslint for TS) and disable irrelevant ones.

---

## Tasks

### Task 1: Project Scaffolding and .gitignore

**Files:**
- Create: `.gitignore`
- Create: `Cargo.toml`
- Create: `src/main.rs` (minimal hello world)

**Step 1: Create comprehensive .gitignore**

```gitignore
# Rust build artifacts
/target/
**/*.rs.bk
*.pdb

# Dependencies
Cargo.lock

# SQLite databases
*.db
*.sqlite
*.sqlite3

# Keys and certificates
certs/
*.pem
*.key
*.crt
*.p12
*.pfx

# Environment files
.env
.env.*
!.env.example

# Log files
*.log
logs/

# Editor/IDE files
.idea/
.vscode/
*.swp
*.swo
*~
.project
.classpath
.settings/
*.sublime-project
*.sublime-workspace
.history/

# OS files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
Desktop.ini
$RECYCLE.BIN/

# Node (for Playwright tests)
node_modules/
tests/e2e/node_modules/
tests/e2e/test-results/
tests/e2e/playwright-report/
tests/e2e/playwright/.auth/

# Fork-join directories
.fork-join/

# Temporary files
*.tmp
*.temp
.cache/
tmp/

# Playwright
playwright-report/
test-results/
blob-report/
```

**Step 2: Create minimal Cargo.toml**

```toml
[package]
name = "sqlite-web-editor"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4.12.1"
actix-rt = "2"
actix-cors = "0.7"
rusqlite = { version = "0.38.0", features = ["bundled"] }
r2d2 = "0.8"
r2d2_sqlite = "0.32.0"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
jsonwebtoken = "10.3.0"
askama = "0.15.4"  # Note: askama_actix is deprecated; askama 0.15+ works directly or via askama_web
base64 = "0.22"
rsa = { version = "0.9.10", features = ["pem"] }
rand = "0.8"
chrono = { version = "0.4", features = ["serde"] }
log = "0.4"
env_logger = "0.11"
dotenv = "0.15"
tokio = { version = "1", features = ["full"] }
```

**Step 3: Create minimal src/main.rs**

```rust
use actix_web::{web, App, HttpServer, HttpResponse};

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

**Step 4: Build and verify**

Run: `cargo build`
Expected: Successful compilation

**Step 5: Commit**

```bash
git add .gitignore Cargo.toml src/main.rs
git commit -m "feat: scaffold project with .gitignore and minimal server"
```

---

### Task 2: JWT Key Infrastructure

**Files:**
- Create: `src/config.rs`
- Create: `src/auth/mod.rs`
- Create: `src/auth/jwt.rs`
- Create: `src/auth/jwks.rs`
- Modify: `src/main.rs`

**Step 1: Write failing test for JWT key generation**

Add to `src/auth/jwt.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_key_pair() {
        let (private_key, public_key) = generate_rsa_key_pair().unwrap();
        assert!(!private_key.is_empty());
        assert!(!public_key.is_empty());
        assert!(private_key.contains("BEGIN RSA PRIVATE KEY"));
        assert!(public_key.contains("BEGIN PUBLIC KEY"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_generate_rsa_key_pair`
Expected: FAIL - function not found

**Step 3: Implement RSA key pair generation**

`src/auth/jwt.rs`:

```rust
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::pkcs8::LineEnding;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn generate_rsa_key_pair() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)?;

    Ok((private_pem.to_string(), public_pem))
}

pub fn ensure_keys(certs_dir: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let priv_path = Path::new(certs_dir).join("private_key.pem");
    let pub_path = Path::new(certs_dir).join("public_key.pem");

    if priv_path.exists() && pub_path.exists() {
        let private_pem = fs::read_to_string(&priv_path)?;
        let public_pem = fs::read_to_string(&pub_path)?;
        return Ok((private_pem, public_pem));
    }

    fs::create_dir_all(certs_dir)?;
    let (private_pem, public_pem) = generate_rsa_key_pair()?;
    fs::write(&priv_path, &private_pem)?;
    fs::write(&pub_path, &public_pem)?;

    Ok((private_pem, public_pem))
}

pub fn create_token(private_key_pem: &str, subject: &str, ttl_seconds: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: subject.to_string(),
        iat: now,
        exp: now + ttl_seconds as usize,
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
    encode(&Header::new(Algorithm::RS256), &claims, &key)
}

pub fn validate_token(public_key_pem: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_key_pair() {
        let (private_key, public_key) = generate_rsa_key_pair().unwrap();
        assert!(!private_key.is_empty());
        assert!(!public_key.is_empty());
        assert!(private_key.contains("BEGIN RSA PRIVATE KEY"));
        assert!(public_key.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_create_and_validate_token() {
        let (private_pem, public_pem) = generate_rsa_key_pair().unwrap();
        let token = create_token(&private_pem, "testuser", 3600).unwrap();
        let claims = validate_token(&public_pem, &token).unwrap();
        assert_eq!(claims.sub, "testuser");
    }

    #[test]
    fn test_expired_token_rejected() {
        let (private_pem, public_pem) = generate_rsa_key_pair().unwrap();
        let token = create_token(&private_pem, "testuser", -10).unwrap();
        assert!(validate_token(&public_pem, &token).is_err());
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All 3 tests PASS

**Step 5: Implement JWKS endpoint**

`src/auth/jwks.rs`:

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use serde::Serialize;

#[derive(Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: String,
    pub r#use: String,
    pub alg: String,
    pub n: String,
    pub e: String,
    pub kid: String,
}

pub fn public_key_to_jwks(public_key_pem: &str) -> Result<Jwks, Box<dyn std::error::Error>> {
    // Parse the PEM to extract RSA components
    let pub_key = RsaPublicKey::from_pkcs1_pem(public_key_pem)
        .or_else(|_| {
            // Try PKCS8 format
            use rsa::pkcs8::DecodePublicKey;
            RsaPublicKey::from_public_key_pem(public_key_pem)
        })?;

    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();

    Ok(Jwks {
        keys: vec![Jwk {
            kty: "RSA".to_string(),
            r#use: "sig".to_string(),
            alg: "RS256".to_string(),
            n: URL_SAFE_NO_PAD.encode(&n),
            e: URL_SAFE_NO_PAD.encode(&e),
            kid: "default".to_string(),
        }],
    })
}
```

**Step 6: Create auth module and wire up**

`src/auth/mod.rs`:

```rust
pub mod jwt;
pub mod jwks;
pub mod middleware;
```

**Step 7: Commit**

```bash
git add src/auth/ src/config.rs
git commit -m "feat: add JWT key generation, token creation/validation, and JWKS"
```

---

### Task 3: Auth Middleware

**Files:**
- Create: `src/auth/middleware.rs`
- Modify: `src/main.rs`

**Step 1: Write the auth middleware**

`src/auth/middleware.rs`:

```rust
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web::body::BoxBody;
use crate::auth::jwt;

pub struct AuthState {
    pub public_key_pem: String,
}

pub fn extract_bearer_token(req: &ServiceRequest) -> Option<String> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

pub fn validate_request(req: &ServiceRequest, public_key_pem: &str) -> Result<jwt::Claims, HttpResponse<BoxBody>> {
    let token = extract_bearer_token(req)
        .ok_or_else(|| HttpResponse::Unauthorized().body("Missing Authorization header"))?;

    jwt::validate_token(public_key_pem, &token)
        .map_err(|e| HttpResponse::Unauthorized().body(format!("Invalid token: {}", e)))
}
```

**Step 2: Write test for middleware token extraction**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn test_extract_bearer_token() {
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer abc123"))
            .to_srv_request();
        assert_eq!(extract_bearer_token(&req), Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let req = TestRequest::default().to_srv_request();
        assert_eq!(extract_bearer_token(&req), None);
    }
}
```

**Step 3: Run tests**

Run: `cargo test`
Expected: PASS

**Step 4: Commit**

```bash
git add src/auth/middleware.rs
git commit -m "feat: add JWT auth middleware with bearer token extraction"
```

---

### Task 4a: Core DB Setup

**Files:**
- Create: `src/db/mod.rs`
- Create: `src/db/connection.rs`

**Step 1: Write failing test for pool creation**

In `src/db/connection.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool() {
        let pool = create_pool(":memory:");
        let conn = pool.get().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_create_pool`
Expected: FAIL

**Step 3: Implement core database setup**

`src/db/connection.rs`:

```rust
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn create_pool(database_url: &str) -> DbPool {
    let manager = SqliteConnectionManager::file(database_url);
    let pool = Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create pool");

    // Enable WAL mode for better concurrency
    let conn = pool.get().expect("Failed to get connection");
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .expect("Failed to set pragmas");

    pool
}
```

`src/db/mod.rs`:

```rust
pub mod connection;
```

**Step 4: Run all tests**

Run: `cargo test`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/db/
git commit -m "feat: add core SQLite database setup with connection pool and WAL mode"
```

---

### Task 4b: Table/Schema CRUD Operations

**Files:**
- Create: `src/db/tables.rs`
- Create: `src/db/schema.rs`
- Modify: `src/db/mod.rs`

**Step 1: Write failing test for table creation**

In `src/db/tables.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_create_table() {
        let conn = Connection::open_in_memory().unwrap();
        create_table(&conn, "test_table", &[("id", "INTEGER"), ("name", "TEXT")]).unwrap();
        let tables = list_tables(&conn).unwrap();
        assert!(tables.contains(&"test_table".to_string()));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_create_table`
Expected: FAIL

**Step 3: Implement table and schema operations**

`src/db/tables.rs`:

```rust
use rusqlite::{Connection, params, Result};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct TableInfo {
    pub name: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ColumnInfo {
    pub cid: i32,
    pub name: String,
    pub col_type: String,
    pub notnull: bool,
    pub dflt_value: Option<String>,
    pub pk: bool,
}

pub fn list_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )?;
    let tables = stmt.query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>>>()?;
    Ok(tables)
}

pub fn create_table(conn: &Connection, name: &str, columns: &[(&str, &str)]) -> Result<()> {
    // Validate table name (alphanumeric + underscore only)
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(rusqlite::Error::InvalidParameterName(
            format!("Invalid table name: {}", name)
        ));
    }

    let cols: Vec<String> = columns.iter()
        .map(|(col_name, col_type)| format!("\"{}\" {}", col_name, col_type))
        .collect();
    let sql = format!("CREATE TABLE \"{}\" ({})", name, cols.join(", "));
    conn.execute(&sql, [])?;
    Ok(())
}

pub fn drop_table(conn: &Connection, name: &str) -> Result<()> {
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(rusqlite::Error::InvalidParameterName(
            format!("Invalid table name: {}", name)
        ));
    }
    let sql = format!("DROP TABLE IF EXISTS \"{}\"", name);
    conn.execute(&sql, [])?;
    Ok(())
}

pub fn get_table_columns(conn: &Connection, table_name: &str) -> Result<Vec<ColumnInfo>> {
    let sql = format!("PRAGMA table_info(\"{}\")", table_name);
    let mut stmt = conn.prepare(&sql)?;
    let columns = stmt.query_map([], |row| {
        Ok(ColumnInfo {
            cid: row.get(0)?,
            name: row.get(1)?,
            col_type: row.get(2)?,
            notnull: row.get(3)?,
            dflt_value: row.get(4)?,
            pk: row.get(5)?,
        })
    })?.collect::<Result<Vec<ColumnInfo>>>()?;
    Ok(columns)
}
```

`src/db/schema.rs`:

```rust
use rusqlite::{Connection, Result};
use super::tables::{get_table_columns, ColumnInfo};

pub fn add_column(conn: &Connection, table_name: &str, col_name: &str, col_type: &str) -> Result<()> {
    if !table_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(rusqlite::Error::InvalidParameterName(
            format!("Invalid table name: {}", table_name)
        ));
    }
    if !col_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(rusqlite::Error::InvalidParameterName(
            format!("Invalid column name: {}", col_name)
        ));
    }

    let sql = format!("ALTER TABLE \"{}\" ADD COLUMN \"{}\" {}", table_name, col_name, col_type);
    conn.execute(&sql, [])?;
    Ok(())
}

pub fn remove_column(conn: &Connection, table_name: &str, col_name: &str) -> Result<()> {
    // SQLite 3.35.0+ supports DROP COLUMN directly
    // For older versions, we'd need the recreate-table approach
    let sql = format!("ALTER TABLE \"{}\" DROP COLUMN \"{}\"", table_name, col_name);
    conn.execute(&sql, [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)", []).unwrap();
        add_column(&conn, "test", "name", "TEXT").unwrap();
        let cols = get_table_columns(&conn, "test").unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[1].name, "name");
    }

    #[test]
    fn test_remove_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)", []).unwrap();
        remove_column(&conn, "test", "age").unwrap();
        let cols = get_table_columns(&conn, "test").unwrap();
        assert_eq!(cols.len(), 2);
        assert!(cols.iter().all(|c| c.name != "age"));
    }
}
```

Update `src/db/mod.rs` to add the new modules:

```rust
pub mod connection;
pub mod tables;
pub mod schema;
```

**Step 4: Run all tests**

Run: `cargo test`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/db/
git commit -m "feat: add table and schema CRUD operations"
```

---

### Task 5a: Base & Auth Templates (Askama)

**Files:**
- Create: `src/templates/base.html`
- Create: `src/templates/login.html`
- Create: `src/templates/partials/alert.html`

**Step 1: Create base template**

`src/templates/base.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SQLite Editor{% endblock %}</title>
    <script src="https://unpkg.com/htmx.org@2.0.8"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 1rem; }
        h1, h2, h3 { margin-bottom: 0.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }
        th { background-color: #f5f5f5; }
        button, .btn { padding: 0.5rem 1rem; cursor: pointer; border: 1px solid #333; background: #fff; border-radius: 4px; }
        button:hover, .btn:hover { background: #f0f0f0; }
        .btn-danger { border-color: #c00; color: #c00; }
        .btn-danger:hover { background: #fee; }
        .btn-primary { background: #0066cc; color: #fff; border-color: #0066cc; }
        .btn-primary:hover { background: #0055aa; }
        input, select { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        form { margin: 1rem 0; }
        .form-group { margin-bottom: 0.5rem; }
        .alert { padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        nav { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid #ddd; margin-bottom: 1rem; }
    </style>
</head>
<body>
    {% block content %}{% endblock %}
</body>
</html>
```

**Step 2: Create login template**

`src/templates/login.html`:

```html
{% extends "base.html" %}
{% block title %}Login - SQLite Editor{% endblock %}
{% block content %}
<nav>
    <h1>SQLite Editor</h1>
</nav>
<div id="login-form">
    <h2>Login</h2>
    <form hx-post="/api/auth/login" hx-target="#login-form" hx-swap="outerHTML">
        <div class="form-group">
            <label for="token">JWT Token:</label>
            <input type="text" id="token" name="token" placeholder="Paste your JWT token" required style="width: 100%;">
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
</div>
{% endblock %}
```

**Step 3: Create alert partial template**

`src/templates/partials/alert.html`:

```html
<div class="alert alert-{{ alert_type }}">{{ message }}</div>
```

**Step 4: Commit**

```bash
git add src/templates/base.html src/templates/login.html src/templates/partials/alert.html
git commit -m "feat: add base layout, login, and alert templates with htmx"
```

---

### Task 5b: Dashboard & Table Detail Templates (Askama)

**Files:**
- Create: `src/templates/dashboard.html`
- Create: `src/templates/table_detail.html`
- Create: `src/templates/partials/table_row.html`
- Create: `src/templates/partials/column_form.html`

**Step 1: Create dashboard template**

`src/templates/dashboard.html`:

```html
{% extends "base.html" %}
{% block title %}Dashboard - SQLite Editor{% endblock %}
{% block content %}
<nav>
    <h1>SQLite Editor</h1>
    <span>Welcome, {{ username }} | <a href="/logout">Logout</a></span>
</nav>

<div id="alerts"></div>

<h2>Tables</h2>
<div id="table-list">
    <table>
        <thead>
            <tr>
                <th>Table Name</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="table-rows">
            {% for table in tables %}
            <tr id="table-{{ table }}">
                <td><a href="/tables/{{ table }}">{{ table }}</a></td>
                <td>
                    <button class="btn btn-danger"
                            hx-delete="/api/tables/{{ table }}"
                            hx-target="#table-{{ table }}"
                            hx-swap="outerHTML"
                            hx-confirm="Drop table '{{ table }}'? This cannot be undone.">
                        Drop
                    </button>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<h3>Create New Table</h3>
<form hx-post="/api/tables"
      hx-target="#table-rows"
      hx-swap="beforeend"
      hx-on::after-request="if(event.detail.successful) this.reset()">
    <div class="form-group">
        <input type="text" name="table_name" placeholder="Table name" required pattern="[a-zA-Z_][a-zA-Z0-9_]*">
        <input type="text" name="first_column_name" placeholder="First column name" required>
        <select name="first_column_type">
            <option value="TEXT">TEXT</option>
            <option value="INTEGER">INTEGER</option>
            <option value="REAL">REAL</option>
            <option value="BLOB">BLOB</option>
        </select>
        <button type="submit" class="btn btn-primary">Create Table</button>
    </div>
</form>
{% endblock %}
```

**Step 2: Create table detail template**

`src/templates/table_detail.html`:

```html
{% extends "base.html" %}
{% block title %}{{ table_name }} - SQLite Editor{% endblock %}
{% block content %}
<nav>
    <h1>SQLite Editor</h1>
    <span><a href="/dashboard">Back to Dashboard</a> | <a href="/logout">Logout</a></span>
</nav>

<h2>Table: {{ table_name }}</h2>
<div id="alerts"></div>

<h3>Columns</h3>
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Not Null</th>
            <th>Primary Key</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody id="column-rows">
        {% for col in columns %}
        <tr id="col-{{ col.name }}">
            <td>{{ col.name }}</td>
            <td>{{ col.col_type }}</td>
            <td>{{ col.notnull }}</td>
            <td>{{ col.pk }}</td>
            <td>
                {% if !col.pk %}
                <button class="btn btn-danger"
                        hx-delete="/api/tables/{{ table_name }}/columns/{{ col.name }}"
                        hx-target="#col-{{ col.name }}"
                        hx-swap="outerHTML"
                        hx-confirm="Remove column '{{ col.name }}'?">
                    Remove
                </button>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>

<h3>Add Column</h3>
<form hx-post="/api/tables/{{ table_name }}/columns"
      hx-target="#column-rows"
      hx-swap="beforeend"
      hx-on::after-request="if(event.detail.successful) this.reset()">
    <div class="form-group">
        <input type="text" name="column_name" placeholder="Column name" required pattern="[a-zA-Z_][a-zA-Z0-9_]*">
        <select name="column_type">
            <option value="TEXT">TEXT</option>
            <option value="INTEGER">INTEGER</option>
            <option value="REAL">REAL</option>
            <option value="BLOB">BLOB</option>
        </select>
        <button type="submit" class="btn btn-primary">Add Column</button>
    </div>
</form>
{% endblock %}
```

**Step 3: Create partial templates**

`src/templates/partials/table_row.html`:

```html
<tr id="table-{{ table_name }}">
    <td><a href="/tables/{{ table_name }}">{{ table_name }}</a></td>
    <td>
        <button class="btn btn-danger"
                hx-delete="/api/tables/{{ table_name }}"
                hx-target="#table-{{ table_name }}"
                hx-swap="outerHTML"
                hx-confirm="Drop table '{{ table_name }}'? This cannot be undone.">
            Drop
        </button>
    </td>
</tr>
```

`src/templates/partials/column_form.html`:

```html
<tr id="col-{{ column_name }}">
    <td>{{ column_name }}</td>
    <td>{{ column_type }}</td>
    <td>false</td>
    <td>false</td>
    <td>
        <button class="btn btn-danger"
                hx-delete="/api/tables/{{ table_name }}/columns/{{ column_name }}"
                hx-target="#col-{{ column_name }}"
                hx-swap="outerHTML"
                hx-confirm="Remove column '{{ column_name }}'?">
            Remove
        </button>
    </td>
</tr>
```

**Step 4: Commit**

```bash
git add src/templates/dashboard.html src/templates/table_detail.html src/templates/partials/table_row.html src/templates/partials/column_form.html
git commit -m "feat: add dashboard and table detail templates with htmx"
```

---

### Task 6a: Auth & Public Route Handlers

**Files:**
- Create: `src/routes/mod.rs`
- Create: `src/routes/auth.rs`
- Create: `src/routes/well_known.rs`

**Step 1: Create routes module**

`src/routes/mod.rs`:

```rust
pub mod auth;
pub mod well_known;
```

**Step 2: Implement .well-known route**

`src/routes/well_known.rs`:

```rust
use actix_web::{web, HttpResponse};
use crate::auth::jwks::public_key_to_jwks;

pub async fn jwks_endpoint(public_key: web::Data<String>) -> HttpResponse {
    match public_key_to_jwks(&public_key) {
        Ok(jwks) => HttpResponse::Ok().json(jwks),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}
```

**Step 3: Implement auth routes**

`src/routes/auth.rs`:

```rust
use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::auth::jwt;

#[derive(Deserialize)]
pub struct LoginForm {
    pub token: String,
}

pub async fn login_page() -> HttpResponse {
    // Render login template
    // Implementation with Askama template rendering
    todo!()
}

pub async fn login(
    form: web::Form<LoginForm>,
    public_key: web::Data<String>,
) -> HttpResponse {
    match jwt::validate_token(&public_key, &form.token) {
        Ok(claims) => {
            // Set auth cookie and redirect to dashboard
            HttpResponse::SeeOther()
                .insert_header(("Location", "/dashboard"))
                .insert_header(("Set-Cookie",
                    format!("auth_token={}; HttpOnly; Path=/; SameSite=Strict", form.token)))
                .finish()
        }
        Err(e) => {
            HttpResponse::Unauthorized().body(format!(
                "<div class='alert alert-error'>Invalid token: {}</div>
                 <form hx-post='/api/auth/login' hx-target='#login-form' hx-swap='outerHTML'>
                     <div class='form-group'>
                         <label for='token'>JWT Token:</label>
                         <input type='text' id='token' name='token' placeholder='Paste your JWT token' required style='width: 100%;'>
                     </div>
                     <button type='submit' class='btn btn-primary'>Login</button>
                 </form>"
            ))
        }
    }
}

pub async fn logout() -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header(("Location", "/"))
        .insert_header(("Set-Cookie", "auth_token=; HttpOnly; Path=/; Max-Age=0"))
        .finish()
}
```

**Step 4: Build and verify**

Run: `cargo build`
Expected: Compiles (some `todo!()` warnings ok for now)

**Step 5: Commit**

```bash
git add src/routes/mod.rs src/routes/auth.rs src/routes/well_known.rs
git commit -m "feat: add auth and public route handlers (login, logout, JWKS)"
```

---

### Task 6b: Table Management Route Handlers

**Files:**
- Create: `src/routes/tables.rs`
- Modify: `src/routes/mod.rs` (add `pub mod tables;`)

**Step 1: Implement table routes**

`src/routes/tables.rs`:

```rust
use actix_web::{web, HttpResponse};
use serde::Deserialize;
use crate::db::connection::DbPool;
use crate::db::tables;

#[derive(Deserialize)]
pub struct CreateTableForm {
    pub table_name: String,
    pub first_column_name: String,
    pub first_column_type: String,
}

pub async fn list_tables(pool: web::Data<DbPool>) -> HttpResponse {
    let conn = pool.get().expect("Failed to get db connection");
    match tables::list_tables(&conn) {
        Ok(table_list) => {
            // Render dashboard template with table list
            todo!()
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

pub async fn table_detail(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> HttpResponse {
    let table_name = path.into_inner();
    let conn = pool.get().expect("Failed to get db connection");
    // Get table schema info and render detail template
    match tables::list_tables(&conn) {
        Ok(_) => {
            // Render table detail template
            todo!()
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

pub async fn create_table(
    pool: web::Data<DbPool>,
    form: web::Form<CreateTableForm>,
) -> HttpResponse {
    let conn = pool.get().expect("Failed to get db connection");
    let columns = vec![(form.first_column_name.as_str(), form.first_column_type.as_str())];
    match tables::create_table(&conn, &form.table_name, &columns) {
        Ok(_) => {
            // Return HTML fragment for htmx to swap in
            HttpResponse::Ok().body(format!(
                "<tr id=\"table-{name}\">
                    <td><a href=\"/tables/{name}\">{name}</a></td>
                    <td>
                        <button class=\"btn btn-danger\"
                                hx-delete=\"/api/tables/{name}\"
                                hx-target=\"#table-{name}\"
                                hx-swap=\"outerHTML\"
                                hx-confirm=\"Drop table '{name}'? This cannot be undone.\">
                            Drop
                        </button>
                    </td>
                </tr>",
                name = form.table_name
            ))
        }
        Err(e) => HttpResponse::BadRequest().body(
            format!("<div class='alert alert-error'>Error creating table: {}</div>", e)
        ),
    }
}

pub async fn delete_table(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> HttpResponse {
    let table_name = path.into_inner();
    let conn = pool.get().expect("Failed to get db connection");
    match tables::drop_table(&conn, &table_name) {
        Ok(_) => HttpResponse::Ok().body(""),  // Empty = element removed by htmx
        Err(e) => HttpResponse::BadRequest().body(
            format!("<div class='alert alert-error'>Error: {}</div>", e)
        ),
    }
}
```

**Step 2: Update routes module**

Add `pub mod tables;` to `src/routes/mod.rs`.

**Step 3: Build and verify**

Run: `cargo build`
Expected: Compiles

**Step 4: Commit**

```bash
git add src/routes/tables.rs src/routes/mod.rs
git commit -m "feat: add table management route handlers (list, detail, create, drop)"
```

---

### Task 6c: Schema Modification Route Handlers

**Files:**
- Create: `src/routes/schema.rs`
- Modify: `src/routes/mod.rs` (add `pub mod schema;`)

**Step 1: Implement schema routes**

`src/routes/schema.rs`:

```rust
use actix_web::{web, HttpResponse};
use serde::Deserialize;
use crate::db::connection::DbPool;
use crate::db::schema;

#[derive(Deserialize)]
pub struct AddColumnForm {
    pub column_name: String,
    pub column_type: String,
}

#[derive(Deserialize)]
pub struct SchemaPath {
    pub table_name: String,
}

#[derive(Deserialize)]
pub struct ColumnPath {
    pub table_name: String,
    pub column_name: String,
}

pub async fn add_column(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    form: web::Form<AddColumnForm>,
) -> HttpResponse {
    let table_name = path.into_inner();
    let conn = pool.get().expect("Failed to get db connection");
    match schema::add_column(&conn, &table_name, &form.column_name, &form.column_type) {
        Ok(_) => {
            HttpResponse::Ok().body(format!(
                "<tr id=\"col-{col}\">
                    <td>{col}</td>
                    <td>{typ}</td>
                    <td>false</td>
                    <td>false</td>
                    <td>
                        <button class=\"btn btn-danger\"
                                hx-delete=\"/api/tables/{tbl}/columns/{col}\"
                                hx-target=\"#col-{col}\"
                                hx-swap=\"outerHTML\"
                                hx-confirm=\"Remove column '{col}'?\">
                            Remove
                        </button>
                    </td>
                </tr>",
                col = form.column_name,
                typ = form.column_type,
                tbl = table_name
            ))
        }
        Err(e) => HttpResponse::BadRequest().body(
            format!("<div class='alert alert-error'>Error: {}</div>", e)
        ),
    }
}

pub async fn remove_column(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (table_name, column_name) = path.into_inner();
    let conn = pool.get().expect("Failed to get db connection");
    match schema::remove_column(&conn, &table_name, &column_name) {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => HttpResponse::BadRequest().body(
            format!("<div class='alert alert-error'>Error: {}</div>", e)
        ),
    }
}
```

**Step 2: Update routes module**

Add `pub mod schema;` to `src/routes/mod.rs`.

**Step 3: Build and verify**

Run: `cargo build`
Expected: Compiles

**Step 4: Commit**

```bash
git add src/routes/schema.rs src/routes/mod.rs
git commit -m "feat: add schema modification route handlers (add/remove column)"
```

---

### Task 7: Complete Template Rendering Integration

**Files:**
- Modify: `src/routes/auth.rs` (replace `todo!()` with template rendering)
- Modify: `src/routes/tables.rs` (replace `todo!()` with template rendering)

**Step 1: Add Askama template structs**

Wire up Askama template structs to each route handler, replacing all `todo!()` calls with actual template rendering using `askama` 0.15+ (note: `askama_actix` is deprecated; use `askama` directly or with `askama_web`).

**Step 2: Add cookie-based auth extraction**

Add a helper function to extract and validate the JWT from the `auth_token` cookie on protected routes (dashboard, table detail). Redirect to login page if the cookie is missing or invalid.

**Step 3: Test manually**

Run: `cargo run`
- Navigate to `http://localhost:8080/` - should see login page
- Navigate to `http://localhost:8080/.well-known/jwks.json` - should see JWKS JSON

**Step 4: Commit**

```bash
git add src/routes/
git commit -m "feat: integrate askama templates with route handlers"
```

---

### Task 8: E2E Test Setup (Playwright)

**Files:**
- Create: `tests/e2e/package.json`
- Create: `tests/e2e/playwright.config.ts`
- Create: `tests/e2e/tsconfig.json`
- Create: `tests/e2e/helpers/jwt.ts`

**Step 1: Initialize Playwright project**

`tests/e2e/package.json`:

```json
{
  "name": "sqlite-web-editor-e2e",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "test": "npx playwright test",
    "test:headed": "npx playwright test --headed",
    "test:report": "npx playwright show-report"
  },
  "devDependencies": {
    "@playwright/test": "^1.58.1",
    "jsonwebtoken": "^9.0.0",
    "@types/jsonwebtoken": "^9.0.0"
  }
}
```

`tests/e2e/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "./dist",
    "rootDir": "."
  }
}
```

**Step 2: Create Playwright config**

`tests/e2e/playwright.config.ts`:

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ['html', { open: 'never' }],
    ['json', { outputFile: 'test-results/results.json' }],
  ],
  use: {
    baseURL: 'http://localhost:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
  webServer: {
    command: 'cargo run',
    cwd: '../../',
    url: 'http://localhost:8080/health',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
```

**Step 3: Create JWT helper for tests**

`tests/e2e/helpers/jwt.ts`:

```typescript
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

export function createTestToken(subject: string = 'testuser', ttlSeconds: number = 60): string {
  const privateKeyPath = path.join(__dirname, '../../../certs/private_key.pem');
  const privateKey = fs.readFileSync(privateKeyPath, 'utf-8');

  return jwt.sign(
    { sub: subject },
    privateKey,
    {
      algorithm: 'RS256',
      expiresIn: ttlSeconds,
    }
  );
}
```

**Step 4: Install dependencies**

Run: `cd tests/e2e && npm install && npx playwright install chromium`

**Step 5: Commit**

```bash
git add tests/e2e/package.json tests/e2e/tsconfig.json tests/e2e/playwright.config.ts tests/e2e/helpers/
git commit -m "feat: set up Playwright E2E test infrastructure with JWT helper"
```

---

### Task 9: E2E Auth Tests

**Files:**
- Create: `tests/e2e/auth.setup.ts`
- Create: `tests/e2e/auth.spec.ts`

**Step 1: Create auth setup**

`tests/e2e/auth.setup.ts`:

```typescript
import { test as setup, expect } from '@playwright/test';
import { createTestToken } from './helpers/jwt';
import path from 'path';

const authFile = path.join(__dirname, 'playwright/.auth/user.json');

setup('authenticate with JWT', async ({ page }) => {
  const token = createTestToken('testuser', 60);  // Short-lived: 60 seconds

  await page.goto('/');
  await page.getByLabel('JWT Token').fill(token);
  await page.getByRole('button', { name: 'Login' }).click();

  await page.waitForURL('/dashboard');
  await expect(page.getByText('Welcome, testuser')).toBeVisible();

  await page.context().storageState({ path: authFile });
});
```

**Step 2: Create auth spec tests**

`tests/e2e/auth.spec.ts`:

```typescript
import { test, expect } from '@playwright/test';
import { createTestToken } from './helpers/jwt';

test.describe('Authentication', () => {
  test('should show login page for unauthenticated users', async ({ page }) => {
    // Clear auth state for this test
    await page.context().clearCookies();
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Login' })).toBeVisible();
    await expect(page.getByLabel('JWT Token')).toBeVisible();
  });

  test('should reject expired JWT tokens', async ({ page }) => {
    await page.context().clearCookies();
    const expiredToken = createTestToken('testuser', -10);
    await page.goto('/');
    await page.getByLabel('JWT Token').fill(expiredToken);
    await page.getByRole('button', { name: 'Login' }).click();
    await expect(page.getByText('Invalid token')).toBeVisible();
  });

  test('should login with valid short-lived JWT token', async ({ page }) => {
    await page.context().clearCookies();
    const token = createTestToken('testuser', 60);
    await page.goto('/');
    await page.getByLabel('JWT Token').fill(token);
    await page.getByRole('button', { name: 'Login' }).click();
    await page.waitForURL('/dashboard');
    await expect(page.getByText('Welcome, testuser')).toBeVisible();
  });

  test('should redirect to login after logout', async ({ page }) => {
    await page.goto('/logout');
    await page.waitForURL('/');
    await expect(page.getByRole('heading', { name: 'Login' })).toBeVisible();
  });
});
```

**Step 3: Run auth tests**

Run: `cd tests/e2e && npx playwright test auth.spec.ts`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add tests/e2e/auth.setup.ts tests/e2e/auth.spec.ts
git commit -m "test: add E2E auth tests with short-lived JWT tokens"
```

---

### Task 10: E2E Table Management Tests

**Files:**
- Create: `tests/e2e/tables.spec.ts`

**Step 1: Write table CRUD tests**

`tests/e2e/tables.spec.ts`:

```typescript
import { test, expect } from '@playwright/test';

test.describe('Table Management', () => {
  test('should create a new table', async ({ page }) => {
    await page.goto('/dashboard');
    await page.getByPlaceholder('Table name').fill('users');
    await page.getByPlaceholder('First column name').fill('id');
    await page.getByRole('combobox').selectOption('INTEGER');
    await page.getByRole('button', { name: 'Create Table' }).click();

    await expect(page.getByRole('link', { name: 'users' })).toBeVisible();
  });

  test('should navigate to table detail view', async ({ page }) => {
    await page.goto('/dashboard');
    await page.getByRole('link', { name: 'users' }).click();
    await page.waitForURL('/tables/users');
    await expect(page.getByRole('heading', { name: 'Table: users' })).toBeVisible();
  });

  test('should drop a table', async ({ page }) => {
    // First create a table to drop
    await page.goto('/dashboard');
    await page.getByPlaceholder('Table name').fill('temp_table');
    await page.getByPlaceholder('First column name').fill('id');
    await page.getByRole('button', { name: 'Create Table' }).click();
    await expect(page.getByRole('link', { name: 'temp_table' })).toBeVisible();

    // Accept the confirmation dialog
    page.on('dialog', dialog => dialog.accept());

    // Drop the table
    const row = page.locator('#table-temp_table');
    await row.getByRole('button', { name: 'Drop' }).click();

    await expect(page.getByRole('link', { name: 'temp_table' })).not.toBeVisible();
  });
});
```

**Step 2: Run table tests**

Run: `cd tests/e2e && npx playwright test tables.spec.ts`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/e2e/tables.spec.ts
git commit -m "test: add E2E tests for table creation and deletion"
```

---

### Task 11: E2E Schema Modification Tests

**Files:**
- Create: `tests/e2e/schema.spec.ts`

**Step 1: Write schema modification tests**

`tests/e2e/schema.spec.ts`:

```typescript
import { test, expect } from '@playwright/test';

test.describe('Schema Modification', () => {
  test.beforeEach(async ({ page }) => {
    // Ensure we have a table to work with
    await page.goto('/dashboard');

    // Create table if it doesn't exist
    const tableLink = page.getByRole('link', { name: 'schema_test' });
    if (!(await tableLink.isVisible().catch(() => false))) {
      await page.getByPlaceholder('Table name').fill('schema_test');
      await page.getByPlaceholder('First column name').fill('id');
      await page.getByRole('combobox').selectOption('INTEGER');
      await page.getByRole('button', { name: 'Create Table' }).click();
      await expect(tableLink).toBeVisible();
    }

    await tableLink.click();
    await page.waitForURL('/tables/schema_test');
  });

  test('should add a column to a table', async ({ page }) => {
    await page.getByPlaceholder('Column name').fill('email');
    await page.locator('select[name="column_type"]').selectOption('TEXT');
    await page.getByRole('button', { name: 'Add Column' }).click();

    await expect(page.locator('#col-email')).toBeVisible();
    await expect(page.locator('#col-email')).toContainText('TEXT');
  });

  test('should remove a column from a table', async ({ page }) => {
    // First add a column to remove
    await page.getByPlaceholder('Column name').fill('temp_col');
    await page.locator('select[name="column_type"]').selectOption('TEXT');
    await page.getByRole('button', { name: 'Add Column' }).click();
    await expect(page.locator('#col-temp_col')).toBeVisible();

    // Accept the confirmation dialog
    page.on('dialog', dialog => dialog.accept());

    // Remove the column
    const colRow = page.locator('#col-temp_col');
    await colRow.getByRole('button', { name: 'Remove' }).click();

    await expect(page.locator('#col-temp_col')).not.toBeVisible();
  });

  test('should show correct column types after adding', async ({ page }) => {
    await page.getByPlaceholder('Column name').fill('age');
    await page.locator('select[name="column_type"]').selectOption('INTEGER');
    await page.getByRole('button', { name: 'Add Column' }).click();

    const colRow = page.locator('#col-age');
    await expect(colRow).toContainText('age');
    await expect(colRow).toContainText('INTEGER');
  });
});
```

**Step 2: Run schema tests**

Run: `cd tests/e2e && npx playwright test schema.spec.ts`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/e2e/schema.spec.ts
git commit -m "test: add E2E tests for schema modification (add/remove columns)"
```

---

### Task 12: GitHub Actions - Lint Workflow

**Files:**
- Create: `.github/workflows/lint.yml`

**Step 1: Create Super-Linter workflow**

`.github/workflows/lint.yml`:

```yaml
name: Lint

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  statuses: write

jobs:
  lint:
    name: Super-Linter
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Super-Linter
        uses: github/super-linter@v8
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          DEFAULT_BRANCH: main
          VALIDATE_RUST_2015: true
          VALIDATE_RUST_2018: true
          VALIDATE_RUST_2021: true
          VALIDATE_RUST_CLIPPY: true
          VALIDATE_TYPESCRIPT_ES: true
          VALIDATE_HTML: true
          VALIDATE_CSS: true
          VALIDATE_YAML: true
          VALIDATE_GITHUB_ACTIONS: true
          FILTER_REGEX_EXCLUDE: "(node_modules|target|tests/e2e/dist)/"
```

**Step 2: Commit**

```bash
git add .github/workflows/lint.yml
git commit -m "ci: add Super-Linter workflow for PR checks"
```

---

### Task 13: GitHub Actions - Dependency Review Workflow

**Files:**
- Create: `.github/workflows/dependency-review.yml`

**Step 1: Create dependency review workflow**

`.github/workflows/dependency-review.yml`:

```yaml
name: Dependency Review

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  dependency-review:
    name: Dependency Review
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4.32.0
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0
```

**Step 2: Commit**

```bash
git add .github/workflows/dependency-review.yml
git commit -m "ci: add dependency review workflow for PR checks"
```

---

### Task 14: GitHub Actions - E2E Test Workflow

**Files:**
- Create: `.github/workflows/e2e-tests.yml`

**Step 1: Create E2E test workflow that uploads results as artifacts**

> **Note:** Test results are uploaded as GitHub Actions artifacts (not committed to the repository). Artifacts are accessible directly from the PR's "Checks" tab, providing validation without polluting the git history with generated files. This is the standard CI approach — committing test results to a branch would create noise in the repo and potential merge conflicts.

`.github/workflows/e2e-tests.yml`:

```yaml
name: E2E Tests

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: read

jobs:
  e2e:
    name: Playwright E2E Tests
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Rust dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/bin/
            ~/.cargo/registry/
            ~/.cargo/git/
            target/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Build Rust backend
        run: cargo build --release

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Playwright dependencies
        working-directory: tests/e2e
        run: |
          npm ci
          npx playwright install --with-deps chromium

      - name: Run E2E tests
        working-directory: tests/e2e
        run: npx playwright test

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: tests/e2e/playwright-report/
          retention-days: 30

      - name: Upload test results JSON
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: tests/e2e/test-results/
          retention-days: 30
```

**Step 2: Commit**

```bash
git add .github/workflows/e2e-tests.yml
git commit -m "ci: add Playwright E2E test workflow with result artifacts"
```

---

### Task 15: Final Integration and Smoke Test

**Files:**
- Modify: various files for integration fixes

**Step 1: Run full build**

Run: `cargo build`
Expected: Clean compilation

**Step 2: Run all Rust unit tests**

Run: `cargo test`
Expected: All tests pass

**Step 3: Run all E2E tests**

Run: `cd tests/e2e && npx playwright test`
Expected: All tests pass

**Step 4: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 5: Run rustfmt**

Run: `cargo fmt --check`
Expected: No formatting issues

**Step 6: Final commit**

```bash
git add -A
git commit -m "feat: complete SQLite web editor with auth, htmx UI, and E2E tests"
```

---

## Spawn Instance and Task Summary

```json
{
  "title": "SQLite Web Editor with JWT Auth and htmx",
  "overview": "A Rust web application using actix-web that lets users authenticate via JWT and manage SQLite databases through an htmx-powered UI. Includes E2E tests with Playwright and CI/CD via GitHub Actions.",
  "spawn_instances": [
    {
      "id": "SPAWN-001",
      "name": "Project Setup and .gitignore",
      "use_spawn_team": false,
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 120",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-001"]
    },
    {
      "id": "SPAWN-002",
      "name": "JWT and Auth Infrastructure",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-002", "CRUISE-003"]
    },
    {
      "id": "SPAWN-003",
      "name": "SQLite Database Layer",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-004a", "CRUISE-004b"]
    },
    {
      "id": "SPAWN-004",
      "name": "Base & Auth Templates, Dashboard & Table Detail Templates",
      "use_spawn_team": false,
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "permissions": ["Read", "Write", "Edit"],
      "task_ids": ["CRUISE-005a", "CRUISE-005b"]
    },
    {
      "id": "SPAWN-005",
      "name": "API Routes and Integration",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-006a", "CRUISE-006b", "CRUISE-006c", "CRUISE-007"]
    },
    {
      "id": "SPAWN-006",
      "name": "E2E Test Infrastructure and Tests",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-008", "CRUISE-009", "CRUISE-010", "CRUISE-011"]
    },
    {
      "id": "SPAWN-007",
      "name": "CI/CD Workflows",
      "use_spawn_team": false,
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 120",
      "permissions": ["Read", "Write", "Edit"],
      "task_ids": ["CRUISE-012", "CRUISE-013", "CRUISE-014"]
    },
    {
      "id": "SPAWN-008",
      "name": "Final Integration and Smoke Test",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-015"]
    }
  ],
  "tasks": [
    {
      "id": "CRUISE-001",
      "subject": "Project scaffolding and .gitignore",
      "description": "Create comprehensive .gitignore (keys, credentials, temp files, build artifacts, node_modules, editor/IDE files, OS files, .env, logs, .fork-join), minimal Cargo.toml with all dependencies, and a hello-world src/main.rs. Verify the project compiles with cargo build.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        ".gitignore exists and covers all specified categories (keys, certs, .env, OS files, editor files, build artifacts, node_modules, .fork-join, logs)",
        "Cargo.toml exists with all required dependencies (actix-web, rusqlite, jsonwebtoken, askama, rsa, etc.)",
        "src/main.rs exists with a /health endpoint",
        "cargo build succeeds"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 120",
      "spawn_instance": "SPAWN-001"
    },
    {
      "id": "CRUISE-002",
      "subject": "JWT key pair generation and token operations",
      "description": "Implement RSA key pair generation (2048-bit), auto-creation of certs/ directory with PEM files, JWT token creation with RS256, and JWT token validation. Include unit tests for key generation, token creation, token validation, and expired token rejection.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "high",
      "acceptance_criteria": [
        "generate_rsa_key_pair() produces valid RSA key pair in PEM format",
        "ensure_keys() creates certs/ directory and PEM files if they don't exist",
        "ensure_keys() reads existing PEM files if they already exist",
        "create_token() produces a valid RS256 JWT with sub, iat, exp claims",
        "validate_token() accepts valid tokens and rejects expired ones",
        "All unit tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-002"
    },
    {
      "id": "CRUISE-003",
      "subject": "JWKS endpoint and auth middleware",
      "description": "Implement the .well-known/jwks.json endpoint that exposes the RSA public key in JWK format. Implement auth middleware that extracts Bearer tokens from Authorization headers and validates them. Include unit tests.",
      "blocked_by": ["CRUISE-002"],
      "complexity": "medium",
      "acceptance_criteria": [
        "public_key_to_jwks() converts PEM to JWKS format with kty, use, alg, n, e, kid fields",
        "extract_bearer_token() extracts token from Authorization: Bearer header",
        "validate_request() returns Claims on valid token or Unauthorized on invalid",
        "All unit tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-002"
    },
    {
      "id": "CRUISE-004a",
      "subject": "Core SQLite database setup",
      "description": "Implement SQLite connection pool using r2d2 with WAL mode enabled. Define the database module structure and connection helpers. Include unit tests verifying pool creation and WAL mode activation using in-memory SQLite.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "medium",
      "acceptance_criteria": [
        "create_pool() creates an r2d2 connection pool with WAL mode enabled",
        "Pool correctly manages connections and handles concurrent access",
        "WAL mode is verified via PRAGMA journal_mode query",
        "All unit tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-003"
    },
    {
      "id": "CRUISE-004b",
      "subject": "Table and schema CRUD operations",
      "description": "Implement table operations (list, create, drop) and schema operations (add column, remove column) on top of the database pool. Include input validation for table and column names. Include unit tests for all operations using in-memory SQLite.",
      "blocked_by": ["CRUISE-004a"],
      "complexity": "medium",
      "acceptance_criteria": [
        "list_tables() returns all non-system tables",
        "create_table() creates a table with specified columns and validates table name",
        "drop_table() drops a table and validates table name",
        "add_column() adds a column via ALTER TABLE",
        "remove_column() removes a column via ALTER TABLE DROP COLUMN",
        "Input validation rejects table/column names with non-alphanumeric characters",
        "All unit tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-003"
    },
    {
      "id": "CRUISE-005a",
      "subject": "Base & Auth Templates",
      "description": "Create Askama HTML templates for the base layout and authentication pages: base layout (with htmx CDN include and CSS) and login page with JWT token submission form.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        "base.html includes htmx script tag and basic CSS",
        "login.html extends base layout and has a form with hx-post for JWT token submission",
        "Alert partial template exists for htmx swap feedback",
        "All htmx attributes use correct hx-target and hx-swap values"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-004"
    },
    {
      "id": "CRUISE-005b",
      "subject": "Dashboard & Table Detail Templates",
      "description": "Create Askama HTML templates for the dashboard (table list with create/drop forms) and table detail (column list with add/remove forms) pages, along with partial fragments for htmx swaps.",
      "blocked_by": ["CRUISE-005a"],
      "complexity": "medium",
      "acceptance_criteria": [
        "dashboard.html extends base layout and lists tables with hx-delete for dropping and a create form with hx-post",
        "table_detail.html extends base layout and lists columns with hx-delete for removal and an add form with hx-post",
        "Partial templates exist for table_row and column_form fragments",
        "All htmx attributes use correct hx-target and hx-swap values"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-004"
    },
    {
      "id": "CRUISE-006a",
      "subject": "Auth & public route handlers",
      "description": "Implement actix-web route handlers for authentication and public endpoints: login page (GET /), login POST (POST /api/auth/login with JWT validation and HttpOnly cookie), logout (GET /logout clears cookie and redirects), and JWKS endpoint (GET /.well-known/jwks.json).",
      "blocked_by": ["CRUISE-003", "CRUISE-005a"],
      "complexity": "medium",
      "acceptance_criteria": [
        "GET / renders login page",
        "POST /api/auth/login validates JWT and sets HttpOnly cookie",
        "GET /logout clears auth cookie and redirects to /",
        "GET /.well-known/jwks.json returns JWKS",
        "All protected routes redirect to login when unauthenticated"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-006b",
      "subject": "Table management route handlers",
      "description": "Implement actix-web route handlers for table management: dashboard (GET /dashboard renders table list, requires valid auth cookie), table detail (GET /tables/:name), create table (POST /api/tables returns htmx fragment), and drop table (DELETE /api/tables/:name).",
      "blocked_by": ["CRUISE-004b", "CRUISE-005b", "CRUISE-006a"],
      "complexity": "medium",
      "acceptance_criteria": [
        "GET /dashboard renders table list (requires valid auth cookie)",
        "GET /tables/:name renders table detail page",
        "POST /api/tables creates a table and returns htmx fragment",
        "DELETE /api/tables/:name drops a table"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-006c",
      "subject": "Schema modification route handlers",
      "description": "Implement actix-web route handlers for schema modifications: add column (POST /api/tables/:name/columns returns htmx fragment) and remove column (DELETE /api/tables/:name/columns/:col).",
      "blocked_by": ["CRUISE-004b", "CRUISE-005b", "CRUISE-006a"],
      "complexity": "low",
      "acceptance_criteria": [
        "POST /api/tables/:name/columns adds a column and returns htmx fragment",
        "DELETE /api/tables/:name/columns/:col removes a column"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-007",
      "subject": "Main.rs wiring and template rendering integration",
      "description": "Wire all routes in main.rs, configure app_data for DbPool and public key, integrate Askama template rendering with route handlers (replace all todo!() calls), and verify the app compiles and starts.",
      "blocked_by": ["CRUISE-006a", "CRUISE-006b", "CRUISE-006c"],
      "complexity": "medium",
      "acceptance_criteria": [
        "main.rs configures all routes with correct HTTP methods",
        "DbPool and public key PEM are shared via app_data",
        "All todo!() calls are replaced with actual template rendering",
        "cargo build succeeds",
        "App starts and serves pages at localhost:8080"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-008",
      "subject": "Playwright test infrastructure setup",
      "description": "Create tests/e2e/ directory with package.json, tsconfig.json, playwright.config.ts (with webServer pointing to cargo run), and JWT helper utility for creating test tokens. Install dependencies and Chromium.",
      "blocked_by": ["CRUISE-007"],
      "complexity": "medium",
      "acceptance_criteria": [
        "tests/e2e/package.json exists with @playwright/test and jsonwebtoken dependencies",
        "tests/e2e/playwright.config.ts configures webServer, projects (setup + chromium), and reporters",
        "tests/e2e/helpers/jwt.ts creates short-lived JWT tokens using the local private key",
        "npm install and playwright install chromium succeed"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-009",
      "subject": "E2E auth tests",
      "description": "Create auth.setup.ts (authenticate with short-lived JWT, save storage state) and auth.spec.ts (test login page visibility, expired token rejection, successful login, logout redirect).",
      "blocked_by": ["CRUISE-008"],
      "complexity": "medium",
      "acceptance_criteria": [
        "auth.setup.ts creates a 60-second JWT, fills the login form, and saves storage state",
        "Test: unauthenticated users see login page",
        "Test: expired tokens are rejected with error message",
        "Test: valid short-lived tokens grant access to dashboard",
        "Test: logout clears session and redirects to login",
        "All auth tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-010",
      "subject": "E2E table management tests",
      "description": "Create tables.spec.ts with tests for creating a new table, navigating to table detail view, and dropping a table (with confirmation dialog handling).",
      "blocked_by": ["CRUISE-009"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Test: create a table and verify it appears in the list",
        "Test: click table name to navigate to detail view",
        "Test: drop a table with confirmation and verify it disappears",
        "All table tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-011",
      "subject": "E2E schema modification tests",
      "description": "Create schema.spec.ts with tests for adding a column (verify name and type appear), removing a column (with confirmation), and verifying correct column types after modification.",
      "blocked_by": ["CRUISE-009"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Test: add a column and verify it appears with correct name and type",
        "Test: remove a column with confirmation and verify it disappears",
        "Test: verify column type is displayed correctly after adding",
        "All schema tests pass"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-012",
      "subject": "GitHub Actions lint workflow",
      "description": "Create .github/workflows/lint.yml using github/super-linter@v8 that runs on PRs to main. Configure for Rust (clippy), TypeScript (eslint), HTML, CSS, YAML, and GitHub Actions validation. Exclude node_modules and target directories.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to main",
        "Uses github/super-linter@v8",
        "Validates Rust (clippy), TypeScript, HTML, CSS, YAML",
        "Excludes node_modules, target, and dist directories"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 120",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-013",
      "subject": "GitHub Actions dependency review workflow",
      "description": "Create .github/workflows/dependency-review.yml using actions/dependency-review-action@v4.32.0 that runs on PRs to main. Configure to fail on moderate+ severity and deny GPL-3.0/AGPL-3.0 licenses.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to main",
        "Uses actions/dependency-review-action@v4.32.0",
        "Fails on moderate or higher severity vulnerabilities",
        "Denies GPL-3.0 and AGPL-3.0 licenses"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 120",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-014",
      "subject": "GitHub Actions E2E test workflow",
      "description": "Create .github/workflows/e2e-tests.yml that builds the Rust backend, installs Playwright, runs E2E tests, and uploads test results as GitHub Actions artifacts (not committed to the repo). Artifacts are accessible from the PR Checks tab for validation. Runs on PRs to main.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to main",
        "Installs Rust, builds with cargo build --release",
        "Installs Node.js 20, npm ci, playwright install chromium",
        "Runs npx playwright test",
        "Uploads playwright-report and test-results as GitHub Actions artifacts (not committed to the repo)",
        "Artifacts retained for 30 days",
        "Workflow permissions are read-only (contents: read, pull-requests: read) since no repo writes are needed"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 120",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-015",
      "subject": "Final integration verification",
      "description": "Run cargo build, cargo test, cargo clippy, cargo fmt --check, and the full Playwright E2E test suite. Fix any issues found. Verify the complete application works end-to-end.",
      "blocked_by": ["CRUISE-007", "CRUISE-010", "CRUISE-011", "CRUISE-014"],
      "complexity": "medium",
      "acceptance_criteria": [
        "cargo build succeeds with no errors",
        "cargo test passes all unit tests",
        "cargo clippy -- -D warnings passes with no warnings",
        "cargo fmt --check passes with no formatting issues",
        "npx playwright test passes all E2E tests",
        "Application serves login page, authenticates, and allows table/schema management"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-008"
    }
  ],
  "risks": [
    "SQLite ALTER TABLE DROP COLUMN requires SQLite 3.35.0+ (bundled rusqlite should include this, but verify)",
    "RSA key pair generation is slow (~1s for 2048-bit) - acceptable for dev startup but test setup needs to reuse keys",
    "htmx swap fragments must return valid HTML; server errors need careful handling to avoid breaking the UI",
    "Playwright webServer config pointing to cargo run may have long startup times - set adequate timeout (120s)",
    "Super-Linter may flag Askama template syntax as invalid HTML - may need VALIDATE_HTML exclusion for templates",
    "Cookie-based auth with JWT tokens means token expiry must be handled gracefully (redirect to login on 401)",
    "Concurrent SQLite writes in E2E tests could cause SQLITE_BUSY errors - WAL mode and single worker should mitigate",
    "The jsonwebtoken npm package and the Rust jsonwebtoken crate must produce compatible RS256 tokens"
  ]
}
```
