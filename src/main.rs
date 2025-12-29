use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tracing::{info, warn};  // Убрано неиспользуемое error

#[derive(Parser, Debug)]
#[command(author, version, about = "iptables AI Analyzer with Ollama")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/iptables-ai/config.toml")]
    config: String,

    /// Mode: report, candidate
    #[arg(short, long, default_value = "report")]
    mode: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    general: GeneralConfig,
    iptables: IptablesConfig,
    ollama: OllamaConfig,
}

#[derive(Deserialize, Debug)]
struct GeneralConfig {
    log_path: String,
    output_dir: String,
}

#[derive(Deserialize, Debug)]
struct IptablesConfig {
    iptables_save_cmd: String,
    iptables_list_cmd: String,
}

#[derive(Deserialize, Debug)]
struct OllamaConfig {
    host: String,
    model: String,
    timeout_secs: u64,
}

#[derive(Debug)]
struct TrafficSummary {
    top_sources: Vec<(String, u64)>,
    top_ports: Vec<(u16, u64)>,
}

#[derive(Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize, Debug)]
struct ChatResponse {
    message: ChatResponseMessage,
}

#[derive(Deserialize, Debug)]
struct ChatResponseMessage {
    content: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct AnalysisResult {
    #[serde(default)]
    findings: Vec<Finding>,
    #[serde(default)]
    suggested_rules: Vec<String>,
    #[serde(default)]
    warnings: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Finding {
    severity: String,
    description: String,
    #[serde(default)]
    related_rules: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting iptables-ai-analyzer in {} mode", args.mode);

    let config_str = fs::read_to_string(&args.config)
        .context("Failed to read config file")?;
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config TOML")?;

    // УБРАНО: let rt = Runtime::new()?.block_on(async { ... })
    // Просто выполняем async код напрямую
    let snapshot = collect_iptables_snapshot(&config.iptables)?;
    let summary = build_summary(&snapshot)?;
    let analysis = analyze_with_ollama(&config.ollama, &snapshot, &summary).await?;

    match args.mode.as_str() {
        "report" => write_report(&config.general, &snapshot, &summary, &analysis)?,
        "candidate" => {
            write_report(&config.general, &snapshot, &summary, &analysis)?;
            write_candidate_script(&config.general, &analysis)?;
        }
        _ => anyhow::bail!("Unknown mode: {}", args.mode),
    }

    info!("Analysis completed successfully");
    Ok(())
}


fn collect_iptables_snapshot(cfg: &IptablesConfig) -> Result<String> {
    info!("Collecting iptables snapshot");

    let output = Command::new(&cfg.iptables_save_cmd)
        .output()
        .context("Failed to run iptables-save")?;

    if !output.status.success() {
        anyhow::bail!("iptables-save failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let rules = String::from_utf8_lossy(&output.stdout).to_string();
    info!("Collected {} bytes of iptables rules", rules.len());
    Ok(rules)
}

fn build_summary(snapshot: &str) -> Result<TrafficSummary> {
    let mut sources: HashMap<String, u64> = HashMap::new();
    // Убрана неиспользуемая переменная ports

    // Парсим строки вида pkts bytes target     prot opt in     out     source               destination
    for line in snapshot.lines() {
        if line.contains("pkts") && line.contains("source") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                if let Ok(pkts) = parts[0].parse::<u64>() {
                    if parts.len() > 8 && !parts[8].is_empty() {
                        *sources.entry(parts[8].to_string()).or_insert(0) += pkts;
                    }
                }
            }
        }
    }

    let mut top_sources: Vec<_> = sources.into_iter().collect();
    top_sources.sort_by(|a, b| b.1.cmp(&a.1));
    top_sources.truncate(10);

    Ok(TrafficSummary {
        top_sources,
        top_ports: vec![], // TODO: парсинг портов
    })
}

async fn analyze_with_ollama(
    cfg: &OllamaConfig,
    snapshot: &str,
    summary: &TrafficSummary,
) -> Result<AnalysisResult> {
    info!("Analyzing with Ollama model: {}", cfg.model);

    let system_prompt = r#"
Ты эксперт по Linux iptables. Получишь фрагмент iptables-save и сводку трафика.
Найди потенциальные проблемы безопасности и предложи исправления.

Ответь ТОЛЬКО в формате JSON:
{
  "findings": [{"severity": "low|medium|high", "description": "...", "related_rules": ["..."]}],
  "suggested_rules": ["iptables -A INPUT -s 1.2.3.4 -j DROP"],
  "warnings": ["..."]
}
    "#.to_string();

    let user_prompt = format!(
        "=== IPTABLES RULES (truncated) ===\n{}\n\n=== TOP SOURCES ===\n{:?}",
        &snapshot[..snapshot.len().min(4000)],
        summary.top_sources
    );

    let request = OllamaChatRequest {
        model: cfg.model.clone(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: system_prompt,
            },
            ChatMessage {
                role: "user".to_string(),
                content: user_prompt,
            },
        ],
        stream: false,
    };

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .build()?;

    let url = format!("{}/api/chat", cfg.host.trim_end_matches('/'));

    // ИСПРАВЛЕНО: Правильная обработка Response (не перемещаем resp)
    let resp = client.post(&url).json(&request).send().await
        .context("Failed to send request to Ollama")?;

    if !resp.status().is_success() {
        // Клонируем status перед вызовом text()
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Ollama error {}: {}", status, err_text);
    }

    let chat_resp: ChatResponse = resp.json().await
        .context("Failed to parse Ollama response")?;

    let content = chat_resp.message.content;
    info!("Received {} chars from Ollama", content.len());

    // Попытка распарсить JSON
    match serde_json::from_str::<AnalysisResult>(&content) {
        Ok(analysis) => Ok(analysis),
        Err(e) => {
            warn!("JSON parse failed: {}. Trying to extract JSON block", e);
            if let Some(json_str) = extract_json_block(&content) {
                serde_json::from_str(&json_str).context("Failed to extract/parse JSON from Ollama response")
            } else {
                anyhow::bail!("Could not extract valid JSON from Ollama response")
            }
        }
    }
}

fn extract_json_block(content: &str) -> Option<String> {
    let re = regex::Regex::new(r#"{[^{}]*(?:\{[^{}]*\}[^{}]*)*}"#).ok()?;
    re.captures(content)
        .and_then(|caps| caps.get(0))
        .map(|m| m.as_str().to_string())
}

fn write_report(
    cfg: &GeneralConfig,
    snapshot: &str,
    summary: &TrafficSummary,
    analysis: &AnalysisResult,
) -> Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    fs::create_dir_all(&cfg.output_dir)?;
    let path = Path::new(&cfg.output_dir)
        .join(format!("report-{}.json", ts));

    let report = serde_json::json!({
        "timestamp": ts,
        "iptables_rules_len": snapshot.len(),
        "traffic_summary": {
            "top_sources": summary.top_sources,
        },
        "analysis": analysis
    });

    fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    info!("Report written to: {:?}", path);
    Ok(())
}

fn write_candidate_script(
    cfg: &GeneralConfig,
    analysis: &AnalysisResult,
) -> Result<()> {
    if analysis.suggested_rules.is_empty() {
        info!("No suggested rules to write");
        return Ok(());
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let candidates_dir = Path::new(&cfg.output_dir).join("candidates");
    fs::create_dir_all(&candidates_dir)?;

    let path = candidates_dir.join(format!("iptables-candidates-{}.sh", ts));
    let mut script = String::from("#!/bin/sh\nset -e\n\n");
    script.push_str("# Backup before applying\n");
    script.push_str("iptables-save > /tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules\n\n");

    for rule in &analysis.suggested_rules {
        script.push_str(rule);
        script.push('\n');
    }

    fs::write(&path, script)?;
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    info!("Candidate script written to: {:?}", path);
    Ok(())
}
