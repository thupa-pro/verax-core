use std::path::PathBuf;
use std::sync::OnceLock;

static PROJECT_CONFIG: OnceLock<AxiomConfig> = OnceLock::new();

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct AxiomConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: Some("axiom-project".into()),
            version: Some("1.0.0".into()),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DefaultsConfig {
    pub algorithm: Option<String>,
    pub key: Option<String>,
    pub predicate: Option<String>,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            algorithm: Some("ed25519".into()),
            key: None,
            predicate: Some("attests".into()),
        }
    }
}

pub fn load_config() -> AxiomConfig {
    if let Some(cfg) = PROJECT_CONFIG.get() {
        return cfg.clone();
    }
    let cfg = load_config_from_disk();
    let _ = PROJECT_CONFIG.set(cfg.clone());
    cfg
}

fn load_config_from_disk() -> AxiomConfig {
    let path = project_config_path();
    if !path.exists() {
        return AxiomConfig::default();
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return AxiomConfig::default(),
    };
    toml::from_str(&content).unwrap_or_default()
}

pub fn project_dir() -> PathBuf {
    PathBuf::from(".axiom")
}

pub fn project_keys_dir() -> PathBuf {
    project_dir().join("keys")
}

pub fn project_cache_dir() -> PathBuf {
    project_dir().join("cache")
}

pub fn project_trust_dir() -> PathBuf {
    project_dir().join("trust")
}

pub fn project_config_path() -> PathBuf {
    project_dir().join("config.toml")
}

pub fn ensure_project_dirs() -> anyhow::Result<()> {
    std::fs::create_dir_all(project_keys_dir())?;
    std::fs::create_dir_all(project_cache_dir())?;
    std::fs::create_dir_all(project_trust_dir())?;
    Ok(())
}
