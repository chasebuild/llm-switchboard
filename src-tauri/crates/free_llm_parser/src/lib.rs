use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub rpm: Option<u32>,
    pub tpm: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub base_urls: Vec<String>,
    pub models: Vec<String>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub source_url: String,
    pub fetched_at: u64,
    pub providers: Vec<Provider>,
}

pub fn parse_markdown(markdown: &str) -> Vec<Provider> {
    let heading_re = Regex::new(r"^###\s+(.*)$").unwrap();
    let link_re = Regex::new(r"\[([^\]]+)\]\([^)]+\)").unwrap();
    let url_re = Regex::new(r"https?://[^\s)]+").unwrap();
    let rpm_re =
        Regex::new(r"(?i)(\d[\d,]*\s*[kK]?)\s*(rpm|requests per minute)").unwrap();
    let tpm_re =
        Regex::new(r"(?i)(\d[\d,]*\s*[kK]?)\s*(tpm|tokens per minute)").unwrap();

    let mut providers: Vec<Provider> = Vec::new();
    let mut current: Option<Provider> = None;
    let mut in_models = false;
    let mut in_description = false;

    for line in markdown.lines() {
        let trimmed = line.trim();
        if let Some(caps) = heading_re.captures(trimmed) {
            if let Some(provider) = current.take() {
                providers.push(provider);
            }

            let raw_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let name = clean_heading(raw_name, &link_re);
            current = Some(Provider {
                name,
                description: String::new(),
                notes: Vec::new(),
                base_urls: Vec::new(),
                models: Vec::new(),
                limits: Limits { rpm: None, tpm: None },
            });
            in_models = false;
            in_description = true;
            continue;
        }

        let Some(provider) = current.as_mut() else {
            continue;
        };

        if trimmed.is_empty() {
            in_models = false;
            in_description = false;
        }

        if is_models_heading(trimmed) {
            in_models = true;
            in_description = false;
        }

        if in_description && !trimmed.is_empty() && provider.description.is_empty() {
            provider.description = strip_markdown_links(trimmed).trim().to_string();
        }

        if in_models {
            if let Some(models) = parse_models_line(trimmed) {
                for model in models {
                    push_unique(&mut provider.models, model);
                }
            }
        } else if let Some(models) = parse_models_inline(trimmed) {
            for model in models {
                push_unique(&mut provider.models, model);
            }
        }

        if !trimmed.is_empty() && !in_models && !is_limits_heading(trimmed) {
            if trimmed.starts_with('-') || trimmed.starts_with('*') {
                let note = trimmed
                    .trim_start_matches(&['-', '*'][..])
                    .trim()
                    .to_string();
                if !note.is_empty() {
                    provider
                        .notes
                        .push(strip_markdown_links(&note).trim().to_string());
                }
            }
        }

        for cap in url_re.captures_iter(trimmed) {
            if let Some(url) = cap.get(0).map(|m| m.as_str()) {
                if looks_like_base_url(url) {
                    push_unique(&mut provider.base_urls, url.to_string());
                }
            }
        }

        if provider.limits.rpm.is_none() {
            if let Some(caps) = rpm_re.captures(trimmed) {
                if let Some(value) = caps.get(1).map(|m| m.as_str()) {
                    provider.limits.rpm = parse_number(value);
                }
            }
        }

        if provider.limits.tpm.is_none() {
            if let Some(caps) = tpm_re.captures(trimmed) {
                if let Some(value) = caps.get(1).map(|m| m.as_str()) {
                    provider.limits.tpm = parse_number(value);
                }
            }
        }
    }

    if let Some(provider) = current.take() {
        providers.push(provider);
    }

    providers.retain(|provider| !provider.name.is_empty());
    providers
}

fn clean_heading(raw: &str, link_re: &Regex) -> String {
    if let Some(caps) = link_re.captures(raw) {
        return caps.get(1).map(|m| m.as_str()).unwrap_or(raw).trim().to_string();
    }
    raw.trim().to_string()
}

fn is_models_heading(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("models")
        || lower.starts_with("model")
        || lower.contains("supported models")
        || lower.contains("available models")
}

fn is_limits_heading(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("limits") || lower.contains("rate limit")
}

fn parse_models_line(line: &str) -> Option<Vec<String>> {
    if let Some(stripped) = line.strip_prefix("- ") {
        return Some(extract_models(stripped));
    }
    if let Some(stripped) = line.strip_prefix("* ") {
        return Some(extract_models(stripped));
    }
    None
}

fn parse_models_inline(line: &str) -> Option<Vec<String>> {
    let lower = line.to_lowercase();
    if lower.starts_with("models:") || lower.starts_with("model:") {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            return Some(extract_models(parts[1]));
        }
    }
    None
}

fn extract_models(raw: &str) -> Vec<String> {
    let mut cleaned = raw.replace('`', "");
    cleaned = cleaned.replace("•", "");
    cleaned = cleaned.replace("·", ",");
    cleaned = cleaned.replace(" / ", ",");

    let mut models = Vec::new();
    for part in cleaned.split(',') {
        let trimmed = strip_markdown_links(part).trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() < 2 {
            continue;
        }
        models.push(trimmed);
    }
    models
}

fn strip_markdown_links(text: &str) -> String {
    let link_re = Regex::new(r"\[([^\]]+)\]\([^)]+\)").unwrap();
    link_re
        .replace_all(text, |caps: &regex::Captures| {
            caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string()
        })
        .to_string()
}

fn parse_number(raw: &str) -> Option<u32> {
    let trimmed = raw.trim().replace(',', "");
    if trimmed.is_empty() {
        return None;
    }
    let (value, multiplier) = if let Some(stripped) = trimmed.strip_suffix('k') {
        (stripped, 1_000)
    } else if let Some(stripped) = trimmed.strip_suffix('K') {
        (stripped, 1_000)
    } else {
        (trimmed.as_str(), 1)
    };

    value.trim().parse::<u32>().ok().map(|v| v * multiplier)
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if list.iter().any(|existing| existing == &value) {
        return;
    }
    list.push(value);
}

fn looks_like_base_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("api")
        || lower.contains("openrouter")
        || lower.contains("generativelanguage")
        || lower.contains("openai")
        || lower.contains("groq")
        || lower.contains("cerebras")
}
