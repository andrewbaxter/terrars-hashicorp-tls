use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;

#[derive(Serialize)]
struct ProviderTlsData {
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
}

struct ProviderTls_ {
    data: RefCell<ProviderTlsData>,
}

pub struct ProviderTls(Rc<ProviderTls_>);

impl ProviderTls {
    pub fn provider_ref(&self) -> String {
        let data = self.0.data.borrow();
        if let Some(alias) = &data.alias {
            format!("{}.{}", "tls", alias)
        } else {
            "tls".into()
        }
    }

    pub fn set_alias(self, alias: impl ToString) -> Self {
        self.0.data.borrow_mut().alias = Some(alias.to_string());
        self
    }
}

impl Provider for ProviderTls_ {
    fn extract_type_tf_id(&self) -> String {
        "tls".into()
    }

    fn extract_provider_type(&self) -> serde_json::Value {
        serde_json::json!({
            "source": "hashicorp/tls",
            "version": "4.0.4",
        })
    }

    fn extract_provider(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildProviderTls {}

impl BuildProviderTls {
    pub fn build(self, stack: &mut Stack) -> ProviderTls {
        let out = ProviderTls(Rc::new(ProviderTls_ { data: RefCell::new(ProviderTlsData { alias: None }) }));
        stack.add_provider(out.0.clone());
        out
    }
}
