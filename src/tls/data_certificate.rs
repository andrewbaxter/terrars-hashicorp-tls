use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;
use super::provider::ProviderTls;

#[derive(Serialize)]
struct DataCertificateData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    #[serde(skip_serializing_if = "SerdeSkipDefault::is_default")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_each: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_chain: Option<PrimField<bool>>,
}

struct DataCertificate_ {
    shared: StackShared,
    tf_id: String,
    data: RefCell<DataCertificateData>,
}

#[derive(Clone)]
pub struct DataCertificate(Rc<DataCertificate_>);

impl DataCertificate {
    fn shared(&self) -> &StackShared {
        &self.0.shared
    }

    pub fn depends_on(self, dep: &impl Referable) -> Self {
        self.0.data.borrow_mut().depends_on.push(dep.extract_ref());
        self
    }

    pub fn set_provider(&self, provider: &ProviderTls) -> &Self {
        self.0.data.borrow_mut().provider = Some(provider.provider_ref());
        self
    }

    #[doc= "Set the field `content`.\nThe content of the certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn set_content(self, v: impl Into<PrimField<String>>) -> Self {
        self.0.data.borrow_mut().content = Some(v.into());
        self
    }

    #[doc= "Set the field `url`.\nURL of the endpoint to get the certificates from. Accepted schemes are: `https`, `tls`. For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket."]
    pub fn set_url(self, v: impl Into<PrimField<String>>) -> Self {
        self.0.data.borrow_mut().url = Some(v.into());
        self
    }

    #[doc= "Set the field `verify_chain`.\nWhether to verify the certificate chain while parsing it or not (default: `true`)."]
    pub fn set_verify_chain(self, v: impl Into<PrimField<bool>>) -> Self {
        self.0.data.borrow_mut().verify_chain = Some(v.into());
        self
    }

    #[doc= "Get a reference to the value of field `certificates` after provisioning.\nThe certificates protecting the site, with the root of the chain first."]
    pub fn certificates(&self) -> ListRef<DataCertificateCertificatesElRef> {
        ListRef::new(self.shared().clone(), format!("{}.certificates", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `content` after provisioning.\nThe content of the certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn content(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.content", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier of this data source: hashing of the certificates in the chain."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `url` after provisioning.\nURL of the endpoint to get the certificates from. Accepted schemes are: `https`, `tls`. For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket."]
    pub fn url(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.url", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `verify_chain` after provisioning.\nWhether to verify the certificate chain while parsing it or not (default: `true`)."]
    pub fn verify_chain(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.verify_chain", self.extract_ref()))
    }
}

impl Referable for DataCertificate {
    fn extract_ref(&self) -> String {
        format!("data.{}.{}", self.0.extract_datasource_type(), self.0.extract_tf_id())
    }
}

impl Datasource for DataCertificate { }

impl ToListMappable for DataCertificate {
    type O = ListRef<DataCertificateRef>;

    fn do_map(self, base: String) -> Self::O {
        self.0.data.borrow_mut().for_each = Some(format!("${{{}}}", base));
        ListRef::new(self.0.shared.clone(), self.extract_ref())
    }
}

impl Datasource_ for DataCertificate_ {
    fn extract_datasource_type(&self) -> String {
        "tls_certificate".into()
    }

    fn extract_tf_id(&self) -> String {
        self.tf_id.clone()
    }

    fn extract_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildDataCertificate {
    pub tf_id: String,
}

impl BuildDataCertificate {
    pub fn build(self, stack: &mut Stack) -> DataCertificate {
        let out = DataCertificate(Rc::new(DataCertificate_ {
            shared: stack.shared.clone(),
            tf_id: self.tf_id,
            data: RefCell::new(DataCertificateData {
                depends_on: core::default::Default::default(),
                provider: None,
                for_each: None,
                content: core::default::Default::default(),
                url: core::default::Default::default(),
                verify_chain: core::default::Default::default(),
            }),
        }));
        stack.add_datasource(out.0.clone());
        out
    }
}

pub struct DataCertificateRef {
    shared: StackShared,
    base: String,
}

impl Ref for DataCertificateRef {
    fn new(shared: StackShared, base: String) -> Self {
        Self {
            shared: shared,
            base: base,
        }
    }
}

impl DataCertificateRef {
    fn shared(&self) -> &StackShared {
        &self.shared
    }

    fn extract_ref(&self) -> String {
        self.base.clone()
    }

    #[doc= "Get a reference to the value of field `certificates` after provisioning.\nThe certificates protecting the site, with the root of the chain first."]
    pub fn certificates(&self) -> ListRef<DataCertificateCertificatesElRef> {
        ListRef::new(self.shared().clone(), format!("{}.certificates", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `content` after provisioning.\nThe content of the certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn content(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.content", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier of this data source: hashing of the certificates in the chain."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `url` after provisioning.\nURL of the endpoint to get the certificates from. Accepted schemes are: `https`, `tls`. For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket."]
    pub fn url(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.url", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `verify_chain` after provisioning.\nWhether to verify the certificate chain while parsing it or not (default: `true`)."]
    pub fn verify_chain(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.verify_chain", self.extract_ref()))
    }
}

#[derive(Serialize)]
pub struct DataCertificateCertificatesEl {
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_pem: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_ca: Option<PrimField<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_algorithm: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_number: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha1_fingerprint: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<PrimField<f64>>,
}

impl DataCertificateCertificatesEl {
    #[doc= "Set the field `cert_pem`.\n"]
    pub fn set_cert_pem(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.cert_pem = Some(v.into());
        self
    }

    #[doc= "Set the field `is_ca`.\n"]
    pub fn set_is_ca(mut self, v: impl Into<PrimField<bool>>) -> Self {
        self.is_ca = Some(v.into());
        self
    }

    #[doc= "Set the field `issuer`.\n"]
    pub fn set_issuer(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.issuer = Some(v.into());
        self
    }

    #[doc= "Set the field `not_after`.\n"]
    pub fn set_not_after(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.not_after = Some(v.into());
        self
    }

    #[doc= "Set the field `not_before`.\n"]
    pub fn set_not_before(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.not_before = Some(v.into());
        self
    }

    #[doc= "Set the field `public_key_algorithm`.\n"]
    pub fn set_public_key_algorithm(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.public_key_algorithm = Some(v.into());
        self
    }

    #[doc= "Set the field `serial_number`.\n"]
    pub fn set_serial_number(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.serial_number = Some(v.into());
        self
    }

    #[doc= "Set the field `sha1_fingerprint`.\n"]
    pub fn set_sha1_fingerprint(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.sha1_fingerprint = Some(v.into());
        self
    }

    #[doc= "Set the field `signature_algorithm`.\n"]
    pub fn set_signature_algorithm(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.signature_algorithm = Some(v.into());
        self
    }

    #[doc= "Set the field `subject`.\n"]
    pub fn set_subject(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.subject = Some(v.into());
        self
    }

    #[doc= "Set the field `version`.\n"]
    pub fn set_version(mut self, v: impl Into<PrimField<f64>>) -> Self {
        self.version = Some(v.into());
        self
    }
}

impl ToListMappable for DataCertificateCertificatesEl {
    type O = BlockAssignable<DataCertificateCertificatesEl>;

    fn do_map(self, base: String) -> Self::O {
        BlockAssignable::Dynamic(DynamicBlock {
            for_each: format!("${{{}}}", base),
            iterator: "each".into(),
            content: self,
        })
    }
}

pub struct BuildDataCertificateCertificatesEl {}

impl BuildDataCertificateCertificatesEl {
    pub fn build(self) -> DataCertificateCertificatesEl {
        DataCertificateCertificatesEl {
            cert_pem: core::default::Default::default(),
            is_ca: core::default::Default::default(),
            issuer: core::default::Default::default(),
            not_after: core::default::Default::default(),
            not_before: core::default::Default::default(),
            public_key_algorithm: core::default::Default::default(),
            serial_number: core::default::Default::default(),
            sha1_fingerprint: core::default::Default::default(),
            signature_algorithm: core::default::Default::default(),
            subject: core::default::Default::default(),
            version: core::default::Default::default(),
        }
    }
}

pub struct DataCertificateCertificatesElRef {
    shared: StackShared,
    base: String,
}

impl Ref for DataCertificateCertificatesElRef {
    fn new(shared: StackShared, base: String) -> DataCertificateCertificatesElRef {
        DataCertificateCertificatesElRef {
            shared: shared,
            base: base.to_string(),
        }
    }
}

impl DataCertificateCertificatesElRef {
    fn shared(&self) -> &StackShared {
        &self.shared
    }

    #[doc= "Get a reference to the value of field `cert_pem` after provisioning.\n"]
    pub fn cert_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_pem", self.base))
    }

    #[doc= "Get a reference to the value of field `is_ca` after provisioning.\n"]
    pub fn is_ca(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.is_ca", self.base))
    }

    #[doc= "Get a reference to the value of field `issuer` after provisioning.\n"]
    pub fn issuer(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.issuer", self.base))
    }

    #[doc= "Get a reference to the value of field `not_after` after provisioning.\n"]
    pub fn not_after(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.not_after", self.base))
    }

    #[doc= "Get a reference to the value of field `not_before` after provisioning.\n"]
    pub fn not_before(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.not_before", self.base))
    }

    #[doc= "Get a reference to the value of field `public_key_algorithm` after provisioning.\n"]
    pub fn public_key_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_algorithm", self.base))
    }

    #[doc= "Get a reference to the value of field `serial_number` after provisioning.\n"]
    pub fn serial_number(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.serial_number", self.base))
    }

    #[doc= "Get a reference to the value of field `sha1_fingerprint` after provisioning.\n"]
    pub fn sha1_fingerprint(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.sha1_fingerprint", self.base))
    }

    #[doc= "Get a reference to the value of field `signature_algorithm` after provisioning.\n"]
    pub fn signature_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.signature_algorithm", self.base))
    }

    #[doc= "Get a reference to the value of field `subject` after provisioning.\n"]
    pub fn subject(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.subject", self.base))
    }

    #[doc= "Get a reference to the value of field `version` after provisioning.\n"]
    pub fn version(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.version", self.base))
    }
}
