use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PanelHttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelRequest {
    pub method: PanelHttpMethod,
    pub api_prefix: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub authenticated: bool,
}

impl PanelRequest {
    pub fn login(email: &str, password: &str) -> Self {
        Self::post(
            "/api/v2",
            "/passport/auth/login",
            false,
            Some(json!({"email": email.trim(), "password": password})),
        )
    }

    pub fn bootstrap() -> Self {
        Self::get("/api/v1", "/app/bootstrap", true, Vec::new())
    }

    pub fn user_info() -> Self {
        Self::get("/api/v1", "/user/info", true, Vec::new())
    }

    pub fn user_subscribe() -> Self {
        Self::get("/api/v1", "/user/getSubscribe", true, Vec::new())
    }

    pub fn servers() -> Self {
        Self::get("/api/v1", "/user/server/fetch", true, Vec::new())
    }

    pub fn sing_box_config_for_server(
        server_id: i64,
        platform: &str,
        core_version: Option<&str>,
    ) -> Self {
        let mut query = vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), platform.to_string()),
            ("server_id".to_string(), server_id.to_string()),
        ];
        if let Some(core_version) = core_version.filter(|item| !item.trim().is_empty()) {
            query.push(("core_version".to_string(), core_version.trim().to_string()));
        }
        Self::get("/api/v1", "/app/config", true, query)
    }

    pub fn sing_box_batch_config(platform: &str, core_version: Option<&str>) -> Self {
        let mut query = vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), platform.to_string()),
        ];
        if let Some(core_version) = core_version.filter(|item| !item.trim().is_empty()) {
            query.push(("core_version".to_string(), core_version.trim().to_string()));
        }
        Self::get("/api/v1", "/app/config", true, query)
    }

    pub fn plans() -> Self {
        Self::get("/api/v1", "/user/plan/fetch", true, Vec::new())
    }

    pub fn payment_methods() -> Self {
        Self::get("/api/v1", "/user/order/getPaymentMethod", true, Vec::new())
    }

    pub fn orders() -> Self {
        Self::get("/api/v1", "/user/order/fetch", true, Vec::new())
    }

    pub fn announcements(current: usize, page_size: usize) -> Self {
        Self::get(
            "/api/v1",
            "/user/notice/fetch",
            true,
            vec![
                ("current".to_string(), current.to_string()),
                ("pageSize".to_string(), page_size.to_string()),
            ],
        )
    }

    fn get(
        api_prefix: &str,
        path: &str,
        authenticated: bool,
        query: Vec<(String, String)>,
    ) -> Self {
        Self {
            method: PanelHttpMethod::Get,
            api_prefix: api_prefix.to_string(),
            path: path.to_string(),
            query,
            body: None,
            authenticated,
        }
    }

    fn post(api_prefix: &str, path: &str, authenticated: bool, body: Option<Value>) -> Self {
        Self {
            method: PanelHttpMethod::Post,
            api_prefix: api_prefix.to_string(),
            path: path.to_string(),
            query: Vec::new(),
            body,
            authenticated,
        }
    }
}
