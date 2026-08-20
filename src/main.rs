use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::DefaultBodyLimit,
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use rust_embed::RustEmbed;
use skyport::{
    api::{self, AppState},
    config, db,
    router::Router as GatewayRouter,
    security,
    vault::Vault,
};

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

#[derive(Parser)]
#[command(name = "skyport", version, about = "Local-first universal AI gateway")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        no_open: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Ui,
    Status,
    Stop,
    Version,
    Keys {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Providers {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    Budget {
        #[command(subcommand)]
        command: BudgetCommand,
    },
    RateLimit {
        #[command(subcommand)]
        command: RateLimitCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Gitcommit {
        #[arg(long)]
        write: bool,
        #[arg(long)]
        workspace: Option<String>,
    },
    Btw {
        question: String,
        #[arg(long)]
        workspace: Option<String>,
    },
    Activity {
        #[arg(long, default_value_t = 30)]
        limit: i64,
        #[arg(long)]
        follow: bool,
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    Add {
        provider: String,
        alias: String,
        #[arg(long, default_value_t = 100)]
        priority: u32,
    },
    List,
    Remove {
        alias: String,
    },
    Replace {
        alias: String,
    },
    Disable {
        alias: String,
    },
    RotateMaster,
}

#[derive(Clone, Copy, ValueEnum)]
enum AuthScopeArg {
    Admin,
    Inference,
}

impl From<AuthScopeArg> for security::TokenScope {
    fn from(value: AuthScopeArg) -> Self {
        match value {
            AuthScopeArg::Admin => Self::Admin,
            AuthScopeArg::Inference => Self::Inference,
        }
    }
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Print a token only when explicitly requested.
    Show { scope: AuthScopeArg },
    /// Revoke the current token and generate a replacement.
    Rotate { scope: AuthScopeArg },
}
#[derive(Subcommand)]
enum ProviderCommand {
    Test { provider: Option<String> },
}
#[derive(Subcommand)]
enum BudgetCommand {
    Set {
        scope: String,
        #[arg(long)]
        monthly: Option<f64>,
        #[arg(long)]
        daily: Option<f64>,
        #[arg(long)]
        rpm: Option<u32>,
    },
}
#[derive(Subcommand)]
enum RateLimitCommand {
    /// Show current global rate limits.
    Show,
    /// Set global rate limits (RPM and/or burst RPS).
    Set {
        #[arg(long)]
        rpm: Option<u32>,
        #[arg(long)]
        rps: Option<u32>,
    },
}

fn print_ascii_banner() {
    let c1 = "\x1b[38;2;56;189;248m"; // Sky 400
    let c2 = "\x1b[38;2;34;211;238m"; // Cyan 400
    let c3 = "\x1b[38;2;99;102;241m"; // Indigo 500
    let c4 = "\x1b[38;2;168;85;247m"; // Purple 500
    let c5 = "\x1b[38;2;236;72;153m"; // Pink 500
    let c6 = "\x1b[38;2;244;63;94m"; // Rose 500

    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let white = "\x1b[37m";
    let reset = "\x1b[0m";

    println!();
    println!("{c1}{bold}  ███████╗██╗  ██╗██╗   ██╗██████╗  ██████╗ ██████╗ ████████╗{reset}");
    println!("{c2}{bold}  ██╔════╝██║ ██╔╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝{reset}");
    println!("{c3}{bold}  ███████╗█████╔╝  ╚████╔╝ ██████╔╝██║   ██║██████╔╝   ██║   {reset}");
    println!("{c4}{bold}  ╚════██║██╔═██╗   ╚██╔╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   {reset}");
    println!("{c5}{bold}  ███████║██║  ██╗   ██║   ██║     ╚██████╔╝██║  ██║   ██║   {reset}");
    println!("{c6}{bold}  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   {reset}");
    println!();
    println!("  {bold}\x1b[48;2;14;165;233;38;2;255;255;255m GATEWAY {reset} \x1b[38;2;148;163;184mLocal-first Universal AI Proxy & Telemetry · v{}{reset}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  {bold}{white}USAGE:{reset}");
    println!("    {cyan}skyport{reset} <COMMAND> [OPTIONS]\n");
    println!("  {bold}{white}CORE COMMANDS:{reset}");
    println!("    {green}{bold}serve{reset}       Start the local AI gateway and web dashboard");
    println!("    {green}{bold}ui{reset}          Open the web control plane in your browser");
    println!(
        "    {green}{bold}activity{reset}    Stream real-time session transcript & tool executions"
    );
    println!("    {green}{bold}keys{reset}        Manage encrypted API keys in the vault (add, list, remove)");
    println!(
        "    {green}{bold}auth{reset}        Show or rotate control plane authentication tokens"
    );
    println!(
        "    {green}{bold}status{reset}      Check if the gateway server is currently running"
    );
    println!("    {green}{bold}stop{reset}        Terminate background gateway instance\n");
    println!("  {bold}{white}DEVELOPER TOOLS:{reset}");
    println!("    {yellow}{bold}providers{reset}   Test credentials and discover models across providers");
    println!(
        "    {yellow}{bold}budget{reset}      Configure spend guardrails, daily & monthly caps"
    );
    println!(
        "    {yellow}{bold}gitcommit{reset}   Generate conventional git commits using utility AI"
    );
    println!("    {yellow}{bold}btw{reset}         Ask natural-language questions about repo & session\n");
    println!("  {dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}");
    println!("  {bold}Quick Start:{reset} Run {cyan}skyport serve{reset} to start the server.");
    println!("  Detailed help: Run {cyan}skyport <command> --help{reset}\n");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("skyport=info")
        .init();
    match Cli::parse().command {
        None => {
            print_ascii_banner();
            Ok(())
        }
        Some(Command::Serve { no_open, yes }) => serve(no_open, yes).await,
        Some(Command::Ui) => {
            open::that("http://localhost:5790")?;
            Ok(())
        }
        Some(Command::Status) => {
            let online = tokio::net::TcpStream::connect("127.0.0.1:5790")
                .await
                .is_ok();
            println!("skyport: {}", if online { "running" } else { "stopped" });
            Ok(())
        }
        Some(Command::Stop) => stop(),
        Some(Command::Version) => {
            println!("skyport {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(Command::Keys { command }) => keys(command),
        Some(Command::Providers { command }) => providers(command).await,
        Some(Command::Budget { command }) => budget(command),
        Some(Command::RateLimit { command }) => rate_limit_command(command),
        Some(Command::Auth { command }) => auth_command(command),
        Some(Command::Gitcommit { write, workspace }) => gitcommit(write, workspace).await,
        Some(Command::Btw {
            question,
            workspace,
        }) => btw(question, workspace).await,
        Some(Command::Activity {
            limit,
            follow,
            clear,
        }) => activity_command(limit, follow, clear).await,
    }
}

async fn serve(no_open: bool, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut cfg = config::load_config()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], cfg.server.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            if config::read_pid().is_ok() {
                println!(
                    "Skyport is already running at http://localhost:{}",
                    cfg.server.port
                );
                if !no_open {
                    let _ = open::that(format!("http://localhost:{}", cfg.server.port));
                }
                return Ok(());
            }
            return Err(format!(
                "Cannot start Skyport: 127.0.0.1:{} is already in use",
                cfg.server.port
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    };

    if !yes {
        print!("Authenticate and launch Skyport gateway with access control? [y/N]: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            eprintln!("Authentication declined. Cannot serve Skyport without authentication.");
            return Ok(());
        }
    }

    if security::initialize_auth_tokens(&mut cfg)? {
        println!("Authentication initialized. Retrieve tokens explicitly with:");
        println!("  skyport auth show admin");
        println!("  skyport auth show inference");
    } else {
        println!("Authentication verified. Gateway running with secure access control.");
    }
    config::save_config(&cfg)?;
    if !yes {
        print!("Need the admin token right now? [y/N]: ");
        std::io::stdout().flush()?;
        let mut token_input = String::new();
        std::io::stdin().read_line(&mut token_input)?;
        let token_answer = token_input.trim().to_lowercase();
        if token_answer == "y" || token_answer == "yes" {
            match security::stored_auth_token(&cfg, security::TokenScope::Admin) {
                Ok(token) => {
                    println!("\nAdmin token (paste into dashboard):");
                    println!("{}", token.as_str());
                    println!();
                }
                Err(error) => eprintln!("Could not retrieve admin token: {}", error),
            }
        }
    }
    let config = Arc::new(RwLock::new(cfg.clone()));
    let vault = Arc::new(RwLock::new(Vault::load_or_create()?));
    let db = db::init_db()?;
    let pruned = db::prune_logs(&db, cfg.telemetry.retention_days)?;
    if pruned > 0 {
        tracing::info!(
            pruned,
            retention_days = cfg.telemetry.retention_days,
            "pruned expired telemetry rows"
        );
    }
    let state = AppState {
        router: Arc::new(GatewayRouter::new(vault.clone(), config.clone())),
        config,
        vault,
        db: Arc::new(std::sync::Mutex::new(db)),
        http_client: reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("skyport/", env!("CARGO_PKG_VERSION")))
            .build()?,
        start_time: std::time::Instant::now(),
        in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        rate_limiter: Arc::new(skyport::rate_limiter::RateLimiter::new()),
        catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
        auth_sessions: std::sync::Arc::new(
            std::sync::RwLock::new(std::collections::HashMap::new()),
        ),
    };
    let app = routes(state.clone())
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.config.clone(),
            security_guard,
        ));
    config::write_pid(std::process::id())?;
    println!("Dashboard: http://localhost:{}", cfg.server.port);
    if !no_open {
        let _ = open::that(format!("http://localhost:{}", cfg.server.port));
    }
    // Discover the model catalog shortly after boot so /v1/models lists real
    // upstream model ids for harnesses that connect to this gateway only.
    {
        let boot_state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = api::admin::refresh_catalog(axum::extract::State(boot_state)).await;
        });
    }
    {
        let cleanup_db = state.db.clone();
        let retention_days = cfg.telemetry.retention_days;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
                if let Ok(db) = cleanup_db.lock() {
                    if db::prune_logs(&db, retention_days).is_err() {
                        tracing::warn!("periodic telemetry pruning failed");
                    }
                }
            }
        });
    }
    // Browser-flow OAuth redirects arrive on the provider's registered loopback
    // callback URI; completing the exchange there keeps the main port free.
    {
        let callback_state = state.clone();
        tokio::spawn(async move {
            let app = Router::new()
                .route("/oauth/callback", get(api::oauth::callback_handler))
                .route(
                    "/",
                    get(|| async {
                        "Skyport OAuth callback — this tab can be closed when the sign-in completes."
                    }),
                )
                .with_state(callback_state);
            let address = SocketAddr::from(([127, 0, 0, 1], api::oauth::CALLBACK_PORT));
            match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => {
                    tracing::info!("OAuth callback listener on {address}");
                    let _ = axum::serve(listener, app).await;
                }
                Err(error) => {
                    tracing::warn!("OAuth callback listener unavailable on {address}: {error}");
                }
            }
        });
    }
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    config::remove_pid();
    result?;
    Ok(())
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/v1/models", get(api::v1::list_models))
        .route("/v1/chat/completions", post(api::v1::chat_completions))
        .route("/v1/embeddings", post(api::v1::embeddings))
        .route("/v1/responses", post(api::v1::responses))
        .route("/api/status", get(api::admin::get_status))
        .route(
            "/api/keys",
            get(api::admin::list_keys).post(api::admin::add_key),
        )
        .route("/api/keys/:alias", delete(api::admin::remove_key))
        .route("/api/keys/:alias/disable", put(api::admin::disable_key))
        .route("/api/keys/:alias/enable", put(api::admin::enable_key))
        .route(
            "/api/config",
            get(api::admin::get_config).put(api::admin::update_config),
        )
        .route("/api/logs", get(api::admin::get_logs_handler))
        .route("/api/traffic", get(api::admin::get_traffic_handler))
        .route("/api/logs/stream", get(api::admin::get_log_stream))
        .route("/api/stats", get(api::admin::get_stats_handler))
        .route(
            "/api/budgets",
            get(api::admin::get_budgets).put(api::admin::update_budgets),
        )
        .route(
            "/api/rate-limit",
            get(api::admin::get_rate_limit).put(api::admin::update_rate_limit),
        )
        .route("/api/providers/test", post(api::admin::test_provider))
        .route("/api/models/refresh", post(api::admin::refresh_catalog))
        .route("/api/models/catalog", get(api::admin::get_catalog))
        .route("/api/skills", get(api::skills::list_skills))
        .route("/api/skills/refresh", post(api::skills::refresh_skills))
        .route("/api/skills/import", post(api::skills::import_custom_skill))
        .route(
            "/api/skills/inspect",
            post(api::skills::inspect_custom_skill),
        )
        .route(
            "/api/skills/:name",
            delete(api::skills::delete_custom_skill),
        )
        .route("/api/skills/:name/enable", put(api::skills::enable_skill))
        .route("/api/skills/:name/disable", put(api::skills::disable_skill))
        .route(
            "/api/providers",
            get(api::admin::get_providers).post(api::admin::update_provider),
        )
        .route(
            "/api/tools/config",
            get(api::tools::get_utility_config).post(api::tools::set_utility_config),
        )
        .route("/api/tools/gitcommit", post(api::tools::gitcommit))
        .route("/api/tools/btw", post(api::tools::btw))
        .route("/api/auth", get(api::oauth::get_auth_status))
        .route("/api/auth/connect", post(api::oauth::connect))
        .route("/api/auth/poll", post(api::oauth::poll))
        .route("/api/auth/paste", post(api::oauth::paste))
        .route("/api/auth/disconnect", post(api::oauth::disconnect))
        .route(
            "/api/activity",
            get(api::admin::get_activity_handler)
                .post(api::admin::add_activity_handler)
                .delete(api::admin::clear_activity_handler),
        )
        .route("/api/activity/stream", get(api::admin::get_activity_stream))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    let asset = Assets::get("index.html").unwrap();
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // the dashboard ships inside the binary; never let a browser pin
            // a stale copy across upgrades
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        asset.data.into_owned(),
    )
}

async fn security_guard(
    axum::extract::State(config): axum::extract::State<Arc<RwLock<skyport::config::SkyportConfig>>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let protected = path.starts_with("/v1/") || path.starts_with("/api/");
    let (port, admin_hash, inference_hash) = match config.read() {
        Ok(config) => (
            config.server.port,
            config.server.admin_token_hash.clone(),
            config.server.inference_token_hash.clone(),
        ),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let host_valid = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| security::valid_host_header(value, port));
    if !host_valid {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if protected
        && request.method() != Method::GET
        && request.method() != Method::HEAD
        && request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !security::valid_browser_origin(value, port))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !protected {
        return next.run(request).await;
    }
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(security::bearer_token);
    let valid = security::authorize_path(
        path,
        token,
        admin_hash.as_deref(),
        inference_hash.as_deref(),
    );
    if !valid {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error":{"message":"Unauthorized","type":"authentication_error","code":"invalid_api_key"}}))).into_response();
    }
    next.run(request).await
}

fn keys(command: KeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    let mut vault = Vault::load_or_create()?;
    match command {
        KeyCommand::Add {
            provider,
            alias,
            priority,
        } => {
            let config = config::load_config()?;
            if !config.providers.contains_key(&provider) {
                return Err("Unknown provider".into());
            }
            let api_key = rpassword::prompt_password("API key: ")?;
            if api_key.trim().is_empty() {
                return Err("API key cannot be empty".into());
            }
            vault.add_key(&provider, &alias, &api_key, priority)?;
            vault.save()?;
            println!("Added {alias}");
        }
        KeyCommand::List => {
            for key in vault.list_keys() {
                println!(
                    "{}\t{}\t{}\t{}",
                    key.key_alias,
                    key.provider,
                    key.masked_key,
                    if key.enabled { "enabled" } else { "disabled" }
                );
            }
        }
        KeyCommand::Remove { alias } => {
            if !vault.remove_key(&alias) {
                return Err("Key not found".into());
            }
            vault.save()?;
        }
        KeyCommand::Replace { alias } => {
            let api_key = rpassword::prompt_password("New API key: ")?;
            if api_key.trim().is_empty() || !vault.replace_key(&alias, &api_key) {
                return Err("Key not found, OAuth-managed, or replacement is empty".into());
            }
            vault.save()?;
        }
        KeyCommand::Disable { alias } => {
            if !vault.disable_key(&alias) {
                return Err("Key not found".into());
            }
            vault.save()?;
        }
        KeyCommand::RotateMaster => {
            vault.rotate_master_key()?;
            println!("Rotated vault master key");
        }
    };
    Ok(())
}
async fn providers(command: ProviderCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config()?;
    match command {
        ProviderCommand::Test { provider } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?;
            for (id, cfg) in cfg
                .providers
                .into_iter()
                .filter(|(id, _)| provider.as_ref().map(|p| p == id).unwrap_or(true))
            {
                let result = client
                    .get(format!("{}/models", cfg.base_url.trim_end_matches('/')))
                    .send()
                    .await;
                println!(
                    "{id}: {}",
                    result
                        .map(|r| r.status().to_string())
                        .unwrap_or_else(|e| e.to_string())
                );
            }
        }
    };
    Ok(())
}
fn budget(command: BudgetCommand) -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config::load_config()?;
    match command {
        BudgetCommand::Set {
            scope,
            monthly,
            daily,
            rpm,
        } => {
            let entry = cfg.budgets.entry(scope).or_default();
            if monthly.is_some() {
                entry.monthly_cap_usd = monthly;
            }
            if daily.is_some() {
                entry.daily_cap_usd = daily;
            }
            if rpm.is_some() {
                entry.max_rpm = rpm;
            }
            config::save_config(&cfg)?;
        }
    };
    Ok(())
}

fn rate_limit_command(command: RateLimitCommand) -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config::load_config()?;
    match command {
        RateLimitCommand::Show => {
            println!("Global Rate Limits:");
            println!(
                "  RPM (Requests/min): {}",
                cfg.rate_limit
                    .max_rpm
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unlimited".to_string())
            );
            println!(
                "  RPS (Burst requests/sec): {}",
                cfg.rate_limit
                    .max_rps
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unlimited".to_string())
            );
        }
        RateLimitCommand::Set { rpm, rps } => {
            if rpm.is_some() {
                cfg.rate_limit.max_rpm = rpm;
            }
            if rps.is_some() {
                cfg.rate_limit.max_rps = rps;
            }
            config::save_config(&cfg)?;
            println!("Global rate limit updated.");
        }
    }
    Ok(())
}

fn auth_command(command: AuthCommand) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = config::load_config()?;
    if security::initialize_auth_tokens(&mut config)? {
        config::save_config(&config)?;
    }
    match command {
        AuthCommand::Show { scope } => {
            let scope = security::TokenScope::from(scope);
            let token = security::stored_auth_token(&config, scope)?;
            println!("{}", token.as_str());
        }
        AuthCommand::Rotate { scope } => {
            let scope = security::TokenScope::from(scope);
            let previous = security::stored_auth_token(&config, scope).ok();
            let token = security::rotate_auth_token(&mut config, scope)?;
            if let Err(error) = config::save_config(&config) {
                if let Some(previous) = previous {
                    security::store_auth_token(scope, &previous)?;
                }
                return Err(error);
            }
            println!("Rotated {} token:", scope.name());
            println!("{}", token.as_str());
            println!("Restart Skyport to load the new verifier.");
        }
    }
    Ok(())
}
fn stop() -> Result<(), Box<dyn std::error::Error>> {
    let pid = config::read_pid()?;
    #[cfg(windows)]
    let status = {
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()?
    };
    #[cfg(unix)]
    let status = {
        std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()?
    };
    if !status.success() {
        return Err(format!("Failed to stop skyport process {pid}").into());
    }
    config::remove_pid();
    Ok(())
}

// ---------------------------------------------------------------------------
// Harness-independent tools (talk to the local gateway over HTTP)
// ---------------------------------------------------------------------------

async fn local_api_client(
) -> Result<(reqwest::Client, String, zeroize::Zeroizing<String>), Box<dyn std::error::Error>> {
    let cfg = config::load_config()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;
    let token = security::stored_auth_token(&cfg, security::TokenScope::Admin)?;
    Ok((
        client,
        format!("http://127.0.0.1:{}", cfg.server.port),
        token,
    ))
}

async fn tool_post(
    path: &str,
    body: serde_json::Value,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let (client, base, auth_key) = local_api_client().await?;
    Ok(client
        .post(format!("{base}{path}"))
        .bearer_auth(auth_key.as_str())
        .json(&body)
        .send()
        .await?)
}

async fn gitcommit(
    write: bool,
    workspace: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = workspace.unwrap_or_else(|| ".".to_string());
    let response = tool_post(
        "/api/tools/gitcommit",
        serde_json::json!({ "workspace": workspace }),
    )
    .await?;
    let payload: serde_json::Value = response.json().await?;
    let message = payload["commit_message"]
        .as_str()
        .ok_or_else(|| {
            payload["error"]
                .as_str()
                .unwrap_or("Unexpected response")
                .to_string()
        })?
        .trim()
        .to_string();
    if message.is_empty() || message.starts_with('-') {
        return Err("Generated commit message is invalid or unsafe".into());
    }
    println!("{message}");
    if write {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["commit", "-m", &message])
            .status()?;
        if !status.success() {
            return Err("git commit failed".into());
        }
    }
    Ok(())
}

async fn btw(
    question: String,
    workspace: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = tool_post(
        "/api/tools/btw",
        serde_json::json!({ "question": question, "workspace": workspace }),
    )
    .await?;
    let payload: serde_json::Value = response.json().await?;
    let answer = payload["answer"]
        .as_str()
        .ok_or_else(|| "Unexpected response".to_string())?;
    println!("{answer}");
    Ok(())
}

async fn activity_command(
    limit: i64,
    follow: bool,
    clear: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = db::init_db()?;
    if clear {
        let deleted = db::clear_activities(&db, None)?;
        println!("Cleared {deleted} activity log entries.");
        return Ok(());
    }

    if follow {
        println!("Following session activity in real time (Ctrl+C to exit)...");
        let mut last_seen_id = 0i64;
        let (entries, _) = db::query_activities(&db, &db::ActivityFilter::default(), limit, 0)?;
        for entry in entries.iter().rev() {
            if let Some(id) = entry.id {
                last_seen_id = last_seen_id.max(id);
            }
            print_activity_line(entry);
        }
        loop {
            tokio::time::sleep(Duration::from_millis(800)).await;
            if let Ok((entries, _)) =
                db::query_activities(&db, &db::ActivityFilter::default(), 20, 0)
            {
                let mut new_items: Vec<_> = entries
                    .into_iter()
                    .filter(|e| e.id.map(|id| id > last_seen_id).unwrap_or(false))
                    .collect();
                new_items.sort_by_key(|e| e.id.unwrap_or(0));
                for entry in new_items {
                    if let Some(id) = entry.id {
                        last_seen_id = last_seen_id.max(id);
                    }
                    print_activity_line(&entry);
                }
            }
        }
    } else {
        let (entries, total) = db::query_activities(&db, &db::ActivityFilter::default(), limit, 0)?;
        if entries.is_empty() {
            println!("No session activity recorded yet.");
            return Ok(());
        }
        for entry in entries.iter().rev() {
            print_activity_line(entry);
        }
        if total > limit {
            println!("\n... ({total} total events, showing last {limit}. Use --limit or --follow)");
        }
    }

    Ok(())
}

fn print_activity_line(entry: &db::ActivityEntry) {
    let time_str = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|_| {
            if entry.timestamp.len() >= 19 {
                entry.timestamp[11..19].to_string()
            } else {
                entry.timestamp.clone()
            }
        });

    let extra = match entry.event_type.as_str() {
        "llm_call" | "test_run" | "command" => entry
            .detail
            .as_deref()
            .map(|d| format!("  \x1b[90m({d})\x1b[0m"))
            .unwrap_or_default(),
        _ => String::new(),
    };

    println!("{time_str}  {}{extra}", entry.title);
}
