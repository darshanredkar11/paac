use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use authz_core::{
    evaluate, Action, AuthzRequest, ContextMap, DecisionEffect, EvaluatorConfig, Principal,
    Relationship, RelationshipKind, Resource, Subject,
};
use authz_identity::{
    group_members_map, save_snapshot, IdentityAdapter, LdapAdapter, LocalFixtureAdapter,
};
use authz_llm_bridge::{LlmRequestBuilder, MockLlmProvider};
use authz_policy::{
    LocalEd25519Signer, PolicyStore, SigningKeyPair,
};
use authz_suggest::{suggest_from_audit, suggest_from_snapshot, write_suggestions, append_audit};
use authz_catalog::{load_catalog, validate_catalog};
use clap::{Parser, Subcommand};
use indexmap::IndexMap;

#[derive(Parser, Debug)]
#[command(name = "authz", version, about = "PAAC — Portable Agent Authorization Control Plane")]
struct Cli {
    #[arg(long, global = true, default_value = "data/policies")]
    policy_dir: PathBuf,
    #[arg(long, global = true, default_value = "data/identity")]
    identity_dir: PathBuf,
    #[arg(long, global = true, default_value = "data/audit/decisions.jsonl")]
    audit_path: PathBuf,
    #[arg(long, global = true, default_value = "data/keys/signing.json")]
    key_path: PathBuf,
    #[command(subcommand)]
    command: Commands,
}


#[derive(Debug)]
struct Paths {
    policy_dir: PathBuf,
    identity_dir: PathBuf,
    audit_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sync identity from an adapter (local|ldap)
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Policy lifecycle
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Authorization check
    Check {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        role: Vec<String>,
        #[arg(long)]
        subject_group: Vec<String>,
        #[arg(long)]
        direct_report: Vec<String>,
        #[arg(long, help = "Interpret NL via mock llm-bridge instead of flags")]
        nl: Option<String>,
    },
    /// Explain a prior decision from audit log
    Explain {
        decision_id: String,
    },
    /// Suggest draft policies from sync/audit
    Suggest,
    /// Validate resource catalog
    Catalog {
        #[command(subcommand)]
        cmd: CatalogCmd,
    },
    /// Run the LLM authorization proxy
    Proxy {
        #[command(subcommand)]
        cmd: ProxyCmd,
    },
}

#[derive(Subcommand, Debug)]
enum CatalogCmd {
    Validate {
        #[arg(long, default_value = "data/catalog/company_resources.yaml")]
        file: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ProxyCmd {
    /// Print how to run paac-proxy (binary from authz-llm-proxy)
    Run {
        #[arg(long, default_value = "paac.toml")]
        config: PathBuf,
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum IdentityCmd {
    /// Sync identity from a single adapter (ldap|ad|entra|cognito|local|all)
    Sync {
        #[arg(default_value = "ldap")]
        source: String,
        #[arg(long, help = "Also write DRAFT policies from groups (never auto-deploy)")]
        drafts: bool,
    },
    /// Auto-discover across all configured LDAP, AD, Entra ID, Cognito, and custom stores
    Discover {
        #[arg(long, default_value_t = true, help = "Write consolidated DRAFT policies from discovered metadata")]
        drafts: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    Validate {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Test,
    Diff {
        #[arg(long)]
        revision: Option<String>,
    },
    Commit {
        #[arg(short, long)]
        message: String,
    },
    Sign,
    Deploy,
    Suggest,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let Cli {
        policy_dir,
        identity_dir,
        audit_path,
        key_path,
        command,
    } = cli;
    let paths = Paths {
        policy_dir,
        identity_dir,
        audit_path,
        key_path,
    };
    match command {
        Commands::Identity { cmd } => match cmd {
            IdentityCmd::Sync { source, drafts } => {
                identity_sync(&paths, &source, drafts).await?;
            }
            IdentityCmd::Discover { drafts } => {
                identity_discover(&paths, drafts).await?;
            }
        },
        Commands::Policy { cmd } => match cmd {
            PolicyCmd::Validate { file } => policy_validate(&paths, file)?,
            PolicyCmd::Test => policy_test(&paths)?,
            PolicyCmd::Diff { revision } => policy_diff(&paths, revision)?,
            PolicyCmd::Commit { message } => policy_commit(&paths, &message)?,
            PolicyCmd::Sign => policy_sign(&paths)?,
            PolicyCmd::Deploy => policy_deploy(&paths)?,
            PolicyCmd::Suggest => suggest_cmd(&paths).await?,
        },
        Commands::Check {
            principal,
            action,
            resource,
            subject,
            role,
            subject_group,
            direct_report,
            nl,
        } => {
            check_cmd(
                &paths,
                principal,
                action,
                resource,
                subject,
                role,
                subject_group,
                direct_report,
                nl,
            )
            .await?;
        }
        Commands::Explain { decision_id } => explain_cmd(&paths, &decision_id)?,
        Commands::Suggest => suggest_cmd(&paths).await?,
        Commands::Catalog { cmd } => match cmd {
            CatalogCmd::Validate { file } => {
                let cat = load_catalog(&file).map_err(|e| anyhow::anyhow!(e))?;
                validate_catalog(&cat).map_err(|e| anyhow::anyhow!(e))?;
                println!("OK: catalog {} ({} resources, {} tools)", file.display(), cat.resources.len(), cat.tools.len());
            }
        },
        Commands::Proxy { cmd } => match cmd {
            ProxyCmd::Run { config, listen } => {
                println!("Start the gateway with:");
                let listen_flag = listen.map(|l| format!(" --listen {l}")).unwrap_or_default();
                println!("  cargo run -p authz-llm-proxy -- --config {}{}", config.display(), listen_flag);
                println!("Or: ./target/release/paac-proxy --config {}{}", config.display(), listen_flag);
            }
        },
    }
    Ok(())
}

async fn identity_discover(cli: &Paths, drafts: bool) -> Result<()> {
    use authz_identity::discover_all_stores;
    let (snap, draft_dsl) = discover_all_stores().await.map_err(|e| anyhow::anyhow!(e))?;
    std::fs::create_dir_all(&cli.identity_dir)?;
    let out = cli.identity_dir.join("snapshot.json");
    save_snapshot(&out, &snap)?;
    println!(
        "Auto-Discovered across all stores (AD, LDAP, Entra ID, Cognito): {} users, {} groups → {}",
        snap.users.len(),
        snap.groups.len(),
        out.display()
    );
    if drafts {
        let store = PolicyStore::open(&cli.policy_dir)?;
        store
            .write_draft("auto-discovered", &draft_dsl)
            .map_err(|e| anyhow::anyhow!(e))?;
        println!(
            "wrote DRAFT policies to {}/drafts/auto-discovered.dsl (never auto-deployed)",
            cli.policy_dir.display()
        );
        println!("--- auto-discovered draft preview ---\n{draft_dsl}");
    }
    Ok(())
}

async fn identity_sync(cli: &Paths, source: &str, drafts: bool) -> Result<()> {
    if source == "all" || source == "discover" {
        return identity_discover(cli, drafts).await;
    }
    let snap = match source {
        "ldap" | "mock-ldap" => {
            let adapter = LdapAdapter::mock_demo();
            adapter.sync().await?
        }
        "ad" | "active_directory" => {
            use authz_identity::{ActiveDirectoryAdapter, ActiveDirectoryConfig, IdpAdapter};
            let adapter = ActiveDirectoryAdapter {
                config: ActiveDirectoryConfig {
                    url: "ldap://localhost:389".into(),
                    bind_dn: "cn=admin,dc=example,dc=com".into(),
                    bind_password: "admin".into(),
                    base_dn: "dc=example,dc=com".into(),
                    mock: true,
                },
            };
            let snap = adapter.sync().await?;
            if drafts {
                let dsl = adapter.draft_policies(&snap);
                let store = PolicyStore::open(&cli.policy_dir)?;
                store.write_draft("ad-sync", &dsl)?;
                println!("wrote DRAFT policies drafts/ad-sync.dsl");
            }
            snap
        }
        "entra" | "entra_id" => {
            use authz_identity::{EntraConfig, EntraIdAdapter, IdpAdapter};
            let adapter = EntraIdAdapter {
                config: EntraConfig {
                    tenant_id: "demo".into(),
                    client_id: "demo".into(),
                    client_secret: String::new(),
                    graph_base: "https://graph.microsoft.com/v1.0".into(),
                    mock: true,
                },
                mock_users: None,
                mock_groups: None,
            };
            let snap = adapter.sync().await?;
            if drafts {
                let dsl = adapter.draft_policies(&snap);
                let store = PolicyStore::open(&cli.policy_dir)?;
                store.write_draft("entra-sync", &dsl)?;
                println!("wrote DRAFT policies drafts/entra-sync.dsl");
            }
            snap
        }
        "cognito" => {
            use authz_identity::{CognitoAdapter, CognitoConfig, IdpAdapter};
            let adapter = CognitoAdapter {
                config: CognitoConfig {
                    region: "us-east-1".into(),
                    user_pool_id: "demo".into(),
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    mock: true,
                    mock_endpoint: None,
                },
                mock_payload: None,
            };
            let snap = adapter.sync().await?;
            if drafts {
                let dsl = adapter.draft_policies(&snap);
                let store = PolicyStore::open(&cli.policy_dir)?;
                store.write_draft("cognito-sync", &dsl)?;
                println!("wrote DRAFT policies drafts/cognito-sync.dsl");
            }
            snap
        }
        "local" => {
            let path = cli.identity_dir.join("fixtures.json");
            let adapter = LocalFixtureAdapter::new(path);
            adapter.sync().await?
        }
        other => bail!("unknown identity source: {other} (use ldap|ad|entra|cognito|local|all)"),
    };
    std::fs::create_dir_all(&cli.identity_dir)?;
    let out = cli.identity_dir.join("snapshot.json");
    save_snapshot(&out, &snap)?;
    println!(
        "synced {} users, {} groups via {source} → {}",
        snap.users.len(),
        snap.groups.len(),
        out.display()
    );
    if drafts {
        let store = PolicyStore::open(&cli.policy_dir)?;
        let dsl = LdapAdapter::write_drafts_to_store(&snap, &store)
            .map_err(|e| anyhow::anyhow!(e))?;
        println!("wrote DRAFT policies to {}/drafts/ldap-sync.dsl (not deployed)", cli.policy_dir.display());
        println!("--- draft preview ---\n{dsl}");
    }
    Ok(())
}

fn policy_validate(cli: &Paths, file: Option<PathBuf>) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let dsl = match file {
        Some(p) => std::fs::read_to_string(p)?,
        None => store.read_active_dsl()?,
    };
    let policies = store.validate_dsl(&dsl)?;
    println!("OK: {} policies validated (DSL → Cedar)", policies.len());
    for p in policies {
        println!("  - {} ({:?} {} {})", p.id, p.effect, p.action, p.resource);
    }
    Ok(())
}

fn policy_test(cli: &Paths) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    // Ensure we have deployed policies; if not, use active DSL in-memory
    let (policy_set, revision, signature) = match store.policy_set_from_deployed() {
        Ok((set, rev)) => {
            let sig = rev.bundle.as_ref().map(|b| b.key_id.clone());
            (set, rev.revision, sig)
        }
        Err(_) => {
            let dsl = store.read_active_dsl()?;
            let policies = store.validate_dsl(&dsl)?;
            let set = Arc::new(authz_policy::cedar_policy_set_from_dsl(&policies)?);
            (set, "uncommitted".into(), None)
        }
    };

    let cases = demo_test_cases();
    let mut failed = 0;
    for (name, req, expect) in cases {
        let cfg = EvaluatorConfig {
            policy_set: policy_set.clone(),
            policy_revision: revision.clone(),
            policy_signature: signature.clone(),
            group_members: HashMap::new(),
        };
        let d = evaluate(&req, &cfg)?;
        let ok = d.effect == expect;
        println!(
            "{} {} — expected {:?}, got {:?} (rev {})",
            if ok { "PASS" } else { "FAIL" },
            name,
            expect,
            d.effect,
            d.evidence.policy_revision
        );
        if !ok {
            failed += 1;
        }
    }
    if failed > 0 {
        bail!("{failed} policy tests failed");
    }
    Ok(())
}

fn demo_test_cases() -> Vec<(&'static str, AuthzRequest, DecisionEffect)> {
    vec![
        (
            "ceo_expense_deny",
            AuthzRequest {
                principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
                action: Action::new("READ"),
                resource: Resource::kind("TRAVEL_EXPENSE"),
                subject: Some(Subject {
                    id: "employee:CEO".into(),
                    kind: "Employee".into(),
                    groups: vec!["EXECUTIVE".into()],
                    attrs: IndexMap::new(),
                }),
                context: ContextMap {
                    values: IndexMap::from([("time_range".into(), "LAST_WEEK".into())]),
                },
                relationships: vec![Relationship {
                    kind: RelationshipKind::DirectReports,
                    from: "user:hr-head".into(),
                    to: "employee:alice".into(),
                }],
                acting_as: None,
                on_behalf_of: None,
            },
            DecisionEffect::Deny,
        ),
        (
            "direct_report_allow",
            AuthzRequest {
                principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
                action: Action::new("READ"),
                resource: Resource::kind("TRAVEL_EXPENSE"),
                subject: Some(Subject {
                    id: "employee:alice".into(),
                    kind: "Employee".into(),
                    groups: vec!["ENGINEERING".into()],
                    attrs: IndexMap::new(),
                }),
                context: ContextMap::default(),
                relationships: vec![Relationship {
                    kind: RelationshipKind::DirectReports,
                    from: "user:hr-head".into(),
                    to: "employee:alice".into(),
                }],
                acting_as: None,
                on_behalf_of: None,
            },
            DecisionEffect::Allow,
        ),
    ]
}

fn policy_diff(cli: &Paths, revision: Option<String>) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let rev = match revision {
        Some(r) => r,
        None => store
            .head_revision()?
            .context("no HEAD revision; commit first")?,
    };
    print!("{}", store.diff_active_vs_revision(&rev)?);
    Ok(())
}

fn policy_commit(cli: &Paths, message: &str) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let rev = store.commit(message)?;
    println!("committed revision {} — {}", rev.revision, rev.message);
    Ok(())
}

fn ensure_key(cli: &Paths) -> Result<LocalEd25519Signer> {
    if cli.key_path.exists() {
        let data = std::fs::read_to_string(&cli.key_path)?;
        let pair: SigningKeyPair = serde_json::from_str(&data)?;
        Ok(LocalEd25519Signer::from_keypair(&pair)?)
    } else {
        if let Some(parent) = cli.key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (signer, pair) = LocalEd25519Signer::generate("key-local-mvp");
        std::fs::write(&cli.key_path, serde_json::to_string_pretty(&pair)?)?;
        println!("generated local signing key → {}", cli.key_path.display());
        Ok(signer)
    }
}

fn policy_sign(cli: &Paths) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let signer = ensure_key(cli)?;
    let bundle = store.sign_head(&signer)?;
    println!(
        "signed revision {} with {} (sha256 {})",
        bundle.revision, bundle.key_id, bundle.content_sha256
    );
    Ok(())
}

fn policy_deploy(cli: &Paths) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let rev = store.deploy_head()?;
    println!("deployed revision {}", rev.revision);
    Ok(())
}

async fn suggest_cmd(cli: &Paths) -> Result<()> {
    let store = PolicyStore::open(&cli.policy_dir)?;
    let mut suggestions = Vec::new();
    let snap_path = cli.identity_dir.join("snapshot.json");
    if snap_path.exists() {
        let snap: authz_identity::IdentitySnapshot =
            serde_json::from_str(&std::fs::read_to_string(snap_path)?)?;
        suggestions.extend(suggest_from_snapshot(&snap));
    }
    suggestions.extend(suggest_from_audit(&cli.audit_path)?);
    if suggestions.is_empty() {
        println!("no suggestions (sync identity or accumulate audit first)");
        return Ok(());
    }
    let written = write_suggestions(&store, &suggestions)?;
    println!("wrote {} draft(s):", written.len());
    for w in written {
        println!("  - drafts/{w}.dsl");
    }
    Ok(())
}

async fn check_cmd(
    cli: &Paths,
    principal: String,
    action: String,
    resource: String,
    subject: Option<String>,
    role: Vec<String>,
    subject_group: Vec<String>,
    direct_report: Vec<String>,
    nl: Option<String>,
) -> Result<()> {
    let req = if let Some(utterance) = nl {
        let bridge = MockLlmProvider {
            default_principal: Principal::with_roles(&principal, role.clone()),
        };
        bridge.build_request(&utterance).await?
    } else {
        let mut relationships = Vec::new();
        for dr in &direct_report {
            relationships.push(Relationship {
                kind: RelationshipKind::DirectReports,
                from: principal.clone(),
                to: dr.clone(),
            });
        }
        AuthzRequest {
            principal: Principal::with_roles(principal, role),
            action: Action::new(action),
            resource: Resource::kind(resource),
            subject: subject.map(|id| Subject {
                id,
                kind: "Employee".into(),
                groups: subject_group,
                attrs: IndexMap::new(),
            }),
            context: ContextMap::default(),
            relationships,
            acting_as: None,
            on_behalf_of: None,
        }
    };

    let store = PolicyStore::open(&cli.policy_dir)?;
    let (policy_set, rev) = store
        .policy_set_from_deployed()
        .context("no deployed policies — run: authz policy commit/sign/deploy")?;

    let mut group_members = HashMap::new();
    let snap_path = cli.identity_dir.join("snapshot.json");
    if snap_path.exists() {
        let snap: authz_identity::IdentitySnapshot =
            serde_json::from_str(&std::fs::read_to_string(snap_path)?)?;
        group_members = group_members_map(&snap);
    }

    let sig = rev.bundle.as_ref().map(|b| b.key_id.clone());
    let cfg = EvaluatorConfig {
        policy_set,
        policy_revision: rev.revision.clone(),
        policy_signature: sig,
        group_members,
    };

    let decision = evaluate(&req, &cfg)?;
    let _ = append_audit(&cli.audit_path, &decision);

    println!("DECISION: {:?}", decision.effect);
    println!("decision_id: {}", decision.evidence.decision_id);
    println!("policy_revision: {}", decision.evidence.policy_revision);
    if let Some(sig) = &decision.evidence.policy_signature {
        println!("policy_signature: {sig}");
    }
    println!("engine_version: {}", decision.evidence.engine_version);
    if let Some(det) = &decision.evidence.determining_policy {
        println!("determining_policy: {} ({:?})", det.id, det.effect);
    }
    for p in &decision.evidence.matched_policies {
        println!("matched_policy: {}", p.id);
    }
    for n in &decision.evidence.notes {
        println!("note: {n}");
    }
    println!(
        "request: {}",
        serde_json::to_string_pretty(&decision.evidence.request)?
    );

    if decision.effect == DecisionEffect::Deny {
        std::process::exit(2);
    }
    Ok(())
}

fn explain_cmd(cli: &Paths, decision_id: &str) -> Result<()> {
    let data = std::fs::read_to_string(&cli.audit_path)
        .with_context(|| format!("audit log {}", cli.audit_path.display()))?;
    for line in data.lines() {
        if line.contains(decision_id) {
            let d: authz_core::AuthzDecision = serde_json::from_str(line)?;
            println!("{}", serde_json::to_string_pretty(&d)?);
            return Ok(());
        }
    }
    bail!("decision {decision_id} not found in audit log");
}
