use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const GEMINI_API_ROOT: &str = "https://generativelanguage.googleapis.com/v1beta";
const MAX_API_KEY_CHARS: usize = 512;
const MAX_MODEL_ID_CHARS: usize = 128;
const MAX_PROMPT_CHARS: usize = 400_000;
const MAX_SYSTEM_INSTRUCTION_CHARS: usize = 32_000;
const MAX_ERROR_BODY_CHARS: usize = 2_000;
const MAX_GENERATE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MODEL_LIST_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiGenerateRequest {
    pub api_key: String,
    pub model: String,
    pub prompt: String,
    pub system_instruction: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiGenerateResponse {
    pub model: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiConnectionRequest {
    pub api_key: String,
    pub model: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiConnectionResponse {
    pub model: String,
    pub verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiModelInfo {
    pub id: String,
    pub display_name: String,
}

fn validate_api_key(api_key: &str) -> Result<&str> {
    let key = api_key.trim();
    if key.is_empty() {
        bail!("Gemini API key is required");
    }
    if key.len() > MAX_API_KEY_CHARS || key.contains(['\r', '\n']) {
        bail!("Gemini API key is invalid");
    }
    Ok(key)
}

fn validate_model_id(model: &str) -> Result<&str> {
    let model = model.trim().strip_prefix("models/").unwrap_or(model.trim());
    if model.is_empty() || model.len() > MAX_MODEL_ID_CHARS {
        bail!("Gemini model ID is invalid");
    }
    if !model
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("Gemini model ID contains unsupported characters");
    }
    Ok(model)
}

fn validate_prompt(prompt: &str, system_instruction: Option<&str>) -> Result<()> {
    if prompt.trim().is_empty() {
        bail!("Gemini prompt is empty");
    }
    if prompt.len() > MAX_PROMPT_CHARS {
        bail!("Gemini prompt exceeds the application safety limit");
    }
    if system_instruction
        .map(|instruction| instruction.len() > MAX_SYSTEM_INSTRUCTION_CHARS)
        .unwrap_or(false)
    {
        bail!("Gemini system instruction exceeds the application safety limit");
    }
    Ok(())
}

fn client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .timeout(timeout)
        .user_agent(format!("logparser-DFIR/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building cloud AI HTTP client")
}

fn sanitize_provider_error(message: &str, api_key: &str) -> String {
    let mut sanitized = message.replace(api_key, "[REDACTED_API_KEY]");
    if let Some(index) = sanitized.to_ascii_lowercase().find("key=") {
        let value_start = index + 4;
        let value_end = sanitized[value_start..]
            .find(|ch: char| ch == '&' || ch.is_whitespace() || ch == '"')
            .map(|offset| value_start + offset)
            .unwrap_or(sanitized.len());
        sanitized.replace_range(value_start..value_end, "[REDACTED_API_KEY]");
    }
    sanitized
}

fn provider_error(status: StatusCode, body: &str, api_key: &str) -> String {
    let parsed_message = serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let fallback: String = body.chars().take(MAX_ERROR_BODY_CHARS).collect();
    let detail = parsed_message.unwrap_or(fallback);
    sanitize_provider_error(
        &format!("Gemini API returned HTTP {}: {}", status.as_u16(), detail),
        api_key,
    )
}

fn extract_generated_text(response: &Value) -> Result<String> {
    let parts = response
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Gemini returned no response content"))?;

    let text = parts
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("");
    if text.trim().is_empty() {
        bail!("Gemini returned an empty response");
    }
    Ok(text)
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<(StatusCode, String)> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("Gemini response exceeds the application safety limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("reading Gemini response")? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            bail!("Gemini response exceeds the application safety limit");
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(body).context("Gemini response was not valid UTF-8")?;
    Ok((status, text))
}

async fn generate(
    api_key: &str,
    model: &str,
    prompt: &str,
    system_instruction: Option<&str>,
    max_output_tokens: Option<u32>,
) -> Result<String> {
    let api_key = validate_api_key(api_key)?;
    let model = validate_model_id(model)?;
    validate_prompt(prompt, system_instruction)?;

    let mut payload = json!({
        "contents": [{
            "role": "user",
            "parts": [{ "text": prompt }]
        }]
    });
    if let Some(instruction) = system_instruction.filter(|value| !value.trim().is_empty()) {
        payload["systemInstruction"] = json!({ "parts": [{ "text": instruction }] });
    }
    if let Some(limit) = max_output_tokens {
        payload["generationConfig"] = json!({ "maxOutputTokens": limit });
    }

    let url = format!("{GEMINI_API_ROOT}/models/{model}:generateContent");
    let response = client(Duration::from_secs(90))?
        .post(url)
        .header("x-goog-api-key", api_key)
        .json(&payload)
        .send()
        .await
        .context("connecting to Gemini")?;
    let (status, body) = read_bounded_response(response, MAX_GENERATE_RESPONSE_BYTES).await?;
    if !status.is_success() {
        bail!(provider_error(status, &body, api_key));
    }
    let response_json: Value = serde_json::from_str(&body).context("parsing Gemini response")?;
    extract_generated_text(&response_json)
}

#[tauri::command]
pub async fn gemini_generate(
    request: GeminiGenerateRequest,
) -> Result<GeminiGenerateResponse, String> {
    let model = validate_model_id(&request.model)
        .map(str::to_string)
        .map_err(|error| error.to_string())?;
    let text = generate(
        &request.api_key,
        &model,
        &request.prompt,
        request.system_instruction.as_deref(),
        None,
    )
    .await
    .map_err(|error| sanitize_provider_error(&error.to_string(), &request.api_key))?;
    Ok(GeminiGenerateResponse { model, text })
}

#[tauri::command]
pub async fn gemini_test_connection(
    request: GeminiConnectionRequest,
) -> Result<GeminiConnectionResponse, String> {
    let model = validate_model_id(&request.model)
        .map(str::to_string)
        .map_err(|error| error.to_string())?;
    generate(&request.api_key, &model, "Reply with OK.", None, Some(8))
        .await
        .map_err(|error| sanitize_provider_error(&error.to_string(), &request.api_key))?;
    Ok(GeminiConnectionResponse {
        model,
        verified: true,
    })
}

#[tauri::command]
pub async fn gemini_list_models(api_key: String) -> Result<Vec<GeminiModelInfo>, String> {
    let api_key = validate_api_key(&api_key)
        .map(str::to_string)
        .map_err(|error| error.to_string())?;
    let client = client(Duration::from_secs(30)).map_err(|error| error.to_string())?;
    let mut page_token: Option<String> = None;
    let mut models = Vec::new();

    for _ in 0..10 {
        let mut request = client
            .get(format!("{GEMINI_API_ROOT}/models"))
            .header("x-goog-api-key", &api_key)
            .query(&[("pageSize", "1000")]);
        if let Some(token) = page_token.as_deref() {
            request = request.query(&[("pageToken", token)]);
        }
        let response = request
            .send()
            .await
            .map_err(|error| sanitize_provider_error(&error.to_string(), &api_key))?;
        let (status, body) = read_bounded_response(response, MAX_MODEL_LIST_RESPONSE_BYTES)
            .await
            .map_err(|error| sanitize_provider_error(&error.to_string(), &api_key))?;
        if !status.is_success() {
            return Err(provider_error(status, &body, &api_key));
        }
        let payload: Value = serde_json::from_str(&body)
            .map_err(|error| format!("Could not parse Gemini model list: {error}"))?;
        if let Some(items) = payload.get("models").and_then(Value::as_array) {
            for item in items {
                let supports_generate = item
                    .get("supportedGenerationMethods")
                    .and_then(Value::as_array)
                    .map(|methods| {
                        methods
                            .iter()
                            .any(|method| method.as_str() == Some("generateContent"))
                    })
                    .unwrap_or(false);
                if !supports_generate {
                    continue;
                }
                let id = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim_start_matches("models/");
                if validate_model_id(id).is_err() {
                    continue;
                }
                let display_name = item
                    .get("displayName")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                models.push(GeminiModelInfo {
                    id: id.to_string(),
                    display_name: display_name.to_string(),
                });
            }
        }
        page_token = payload
            .get("nextPageToken")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_string);
        if page_token.is_none() {
            break;
        }
    }

    models.sort_by(|left, right| left.id.cmp(&right.id));
    models.dedup_by(|left, right| left.id == right.id);
    Ok(models)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_ids_are_restricted_to_a_single_safe_path_segment() {
        assert_eq!(
            validate_model_id("models/gemini-2.5-flash").unwrap(),
            "gemini-2.5-flash"
        );
        assert!(validate_model_id("../secrets").is_err());
        assert!(validate_model_id("gemini/model").is_err());
        assert!(validate_model_id("gemini?key=secret").is_err());
    }

    #[test]
    fn provider_errors_never_return_the_api_key() {
        let key = "AIzaSy-sensitive-test-key";
        let sanitized = sanitize_provider_error(
            "request failed: https://example.invalid?key=AIzaSy-sensitive-test-key&x=1",
            key,
        );
        assert!(!sanitized.contains(key));
        assert!(sanitized.contains("[REDACTED_API_KEY]"));
    }

    #[test]
    fn generated_text_joins_all_text_parts() {
        let response = json!({
            "candidates": [{
                "content": { "parts": [{ "text": "hello " }, { "text": "world" }] }
            }]
        });
        assert_eq!(extract_generated_text(&response).unwrap(), "hello world");
    }
}
