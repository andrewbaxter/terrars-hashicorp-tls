use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;
use super::provider::ProviderTls;

#[derive(Serialize)]
struct LocallySignedCertData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "SerdeSkipDefault::is_default")]
    lifecycle: ResourceLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_each: Option<String>,
    allowed_uses: ListField<PrimField<String>>,
    ca_cert_pem: PrimField<String>,
    ca_private_key_pem: PrimField<String>,
    cert_request_pem: PrimField<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    early_renewal_hours: Option<PrimField<f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_ca_certificate: Option<PrimField<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_subject_key_id: Option<PrimField<bool>>,
    validity_period_hours: PrimField<f64>,
}

struct LocallySignedCert_ {
    shared: StackShared,
    tf_id: String,
    data: RefCell<LocallySignedCertData>,
}

#[derive(Clone)]
pub struct LocallySignedCert(Rc<LocallySignedCert_>);

impl LocallySignedCert {
    fn shared(&self) -> &StackShared {
        &self.0.shared
    }

    pub fn depends_on(self, dep: &impl Referable) -> Self {
        self.0.data.borrow_mut().depends_on.push(dep.extract_ref());
        self
    }

    pub fn set_provider(self, provider: &ProviderTls) -> Self {
        self.0.data.borrow_mut().provider = Some(provider.provider_ref());
        self
    }

    pub fn set_create_before_destroy(self, v: bool) -> Self {
        self.0.data.borrow_mut().lifecycle.create_before_destroy = v;
        self
    }

    pub fn set_prevent_destroy(self, v: bool) -> Self {
        self.0.data.borrow_mut().lifecycle.prevent_destroy = v;
        self
    }

    pub fn ignore_changes_to_all(self) -> Self {
        self.0.data.borrow_mut().lifecycle.ignore_changes = Some(IgnoreChanges::All(IgnoreChangesAll::All));
        self
    }

    pub fn ignore_changes_to_attr(self, attr: impl ToString) -> Self {
        {
            let mut d = self.0.data.borrow_mut();
            if match &mut d.lifecycle.ignore_changes {
                Some(i) => match i {
                    IgnoreChanges::All(_) => {
                        true
                    },
                    IgnoreChanges::Refs(r) => {
                        r.push(attr.to_string());
                        false
                    },
                },
                None => true,
            } {
                d.lifecycle.ignore_changes = Some(IgnoreChanges::Refs(vec![attr.to_string()]));
            }
        }
        self
    }

    pub fn replace_triggered_by_resource(self, r: &impl Resource) -> Self {
        self.0.data.borrow_mut().lifecycle.replace_triggered_by.push(r.extract_ref());
        self
    }

    pub fn replace_triggered_by_attr(self, attr: impl ToString) -> Self {
        self.0.data.borrow_mut().lifecycle.replace_triggered_by.push(attr.to_string());
        self
    }

    #[doc= "Set the field `early_renewal_hours`.\nThe resource will consider the certificate to have expired the given number of hours before its actual expiry time. This can be useful to deploy an updated certificate in advance of the expiration of the current certificate. However, the old certificate remains valid until its true expiration time, since this resource does not (and cannot) support certificate revocation. Also, this advance update can only be performed should the Terraform configuration be applied during the early renewal period. (default: `0`)"]
    pub fn set_early_renewal_hours(self, v: impl Into<PrimField<f64>>) -> Self {
        self.0.data.borrow_mut().early_renewal_hours = Some(v.into());
        self
    }

    #[doc= "Set the field `is_ca_certificate`.\nIs the generated certificate representing a Certificate Authority (CA) (default: `false`)."]
    pub fn set_is_ca_certificate(self, v: impl Into<PrimField<bool>>) -> Self {
        self.0.data.borrow_mut().is_ca_certificate = Some(v.into());
        self
    }

    #[doc= "Set the field `set_subject_key_id`.\nShould the generated certificate include a [subject key identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2) (default: `false`)."]
    pub fn set_set_subject_key_id(self, v: impl Into<PrimField<bool>>) -> Self {
        self.0.data.borrow_mut().set_subject_key_id = Some(v.into());
        self
    }

    #[doc= "Get a reference to the value of field `allowed_uses` after provisioning.\nList of key usages allowed for the issued certificate. Values are defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and combine flags defined by both [Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) and [Extended Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12). Accepted values: `any_extended`, `cert_signing`, `client_auth`, `code_signing`, `content_commitment`, `crl_signing`, `data_encipherment`, `decipher_only`, `digital_signature`, `email_protection`, `encipher_only`, `ipsec_end_system`, `ipsec_tunnel`, `ipsec_user`, `key_agreement`, `key_encipherment`, `microsoft_commercial_code_signing`, `microsoft_kernel_code_signing`, `microsoft_server_gated_crypto`, `netscape_server_gated_crypto`, `ocsp_signing`, `server_auth`, `timestamping`."]
    pub fn allowed_uses(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.allowed_uses", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_cert_pem` after provisioning.\nCertificate data of the Certificate Authority (CA) in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn ca_cert_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_cert_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_key_algorithm` after provisioning.\nName of the algorithm used when generating the private key provided in `ca_private_key_pem`. "]
    pub fn ca_key_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_key_algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_private_key_pem` after provisioning.\nPrivate key of the Certificate Authority (CA) used to sign the certificate, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn ca_private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `cert_pem` after provisioning.\nCertificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn cert_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `cert_request_pem` after provisioning.\nCertificate request data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn cert_request_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_request_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `early_renewal_hours` after provisioning.\nThe resource will consider the certificate to have expired the given number of hours before its actual expiry time. This can be useful to deploy an updated certificate in advance of the expiration of the current certificate. However, the old certificate remains valid until its true expiration time, since this resource does not (and cannot) support certificate revocation. Also, this advance update can only be performed should the Terraform configuration be applied during the early renewal period. (default: `0`)"]
    pub fn early_renewal_hours(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.early_renewal_hours", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: the certificate serial number."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `is_ca_certificate` after provisioning.\nIs the generated certificate representing a Certificate Authority (CA) (default: `false`)."]
    pub fn is_ca_certificate(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.is_ca_certificate", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ready_for_renewal` after provisioning.\nIs the certificate either expired (i.e. beyond the `validity_period_hours`) or ready for an early renewal (i.e. within the `early_renewal_hours`)?"]
    pub fn ready_for_renewal(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.ready_for_renewal", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `set_subject_key_id` after provisioning.\nShould the generated certificate include a [subject key identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2) (default: `false`)."]
    pub fn set_subject_key_id(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.set_subject_key_id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_end_time` after provisioning.\nThe time until which the certificate is invalid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp."]
    pub fn validity_end_time(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_end_time", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_period_hours` after provisioning.\nNumber of hours, after initial issuing, that the certificate will remain valid for."]
    pub fn validity_period_hours(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_period_hours", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_start_time` after provisioning.\nThe time after which the certificate is valid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp."]
    pub fn validity_start_time(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_start_time", self.extract_ref()))
    }
}

impl Referable for LocallySignedCert {
    fn extract_ref(&self) -> String {
        format!("{}.{}", self.0.extract_resource_type(), self.0.extract_tf_id())
    }
}

impl Resource for LocallySignedCert { }

impl ToListMappable for LocallySignedCert {
    type O = ListRef<LocallySignedCertRef>;

    fn do_map(self, base: String) -> Self::O {
        self.0.data.borrow_mut().for_each = Some(format!("${{{}}}", base));
        ListRef::new(self.0.shared.clone(), self.extract_ref())
    }
}

impl Resource_ for LocallySignedCert_ {
    fn extract_resource_type(&self) -> String {
        "tls_locally_signed_cert".into()
    }

    fn extract_tf_id(&self) -> String {
        self.tf_id.clone()
    }

    fn extract_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildLocallySignedCert {
    pub tf_id: String,
    #[doc= "List of key usages allowed for the issued certificate. Values are defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and combine flags defined by both [Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) and [Extended Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12). Accepted values: `any_extended`, `cert_signing`, `client_auth`, `code_signing`, `content_commitment`, `crl_signing`, `data_encipherment`, `decipher_only`, `digital_signature`, `email_protection`, `encipher_only`, `ipsec_end_system`, `ipsec_tunnel`, `ipsec_user`, `key_agreement`, `key_encipherment`, `microsoft_commercial_code_signing`, `microsoft_kernel_code_signing`, `microsoft_server_gated_crypto`, `netscape_server_gated_crypto`, `ocsp_signing`, `server_auth`, `timestamping`."]
    pub allowed_uses: ListField<PrimField<String>>,
    #[doc= "Certificate data of the Certificate Authority (CA) in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub ca_cert_pem: PrimField<String>,
    #[doc= "Private key of the Certificate Authority (CA) used to sign the certificate, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub ca_private_key_pem: PrimField<String>,
    #[doc= "Certificate request data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub cert_request_pem: PrimField<String>,
    #[doc= "Number of hours, after initial issuing, that the certificate will remain valid for."]
    pub validity_period_hours: PrimField<f64>,
}

impl BuildLocallySignedCert {
    pub fn build(self, stack: &mut Stack) -> LocallySignedCert {
        let out = LocallySignedCert(Rc::new(LocallySignedCert_ {
            shared: stack.shared.clone(),
            tf_id: self.tf_id,
            data: RefCell::new(LocallySignedCertData {
                depends_on: core::default::Default::default(),
                provider: None,
                lifecycle: core::default::Default::default(),
                for_each: None,
                allowed_uses: self.allowed_uses,
                ca_cert_pem: self.ca_cert_pem,
                ca_private_key_pem: self.ca_private_key_pem,
                cert_request_pem: self.cert_request_pem,
                early_renewal_hours: core::default::Default::default(),
                is_ca_certificate: core::default::Default::default(),
                set_subject_key_id: core::default::Default::default(),
                validity_period_hours: self.validity_period_hours,
            }),
        }));
        stack.add_resource(out.0.clone());
        out
    }
}

pub struct LocallySignedCertRef {
    shared: StackShared,
    base: String,
}

impl Ref for LocallySignedCertRef {
    fn new(shared: StackShared, base: String) -> Self {
        Self {
            shared: shared,
            base: base,
        }
    }
}

impl LocallySignedCertRef {
    fn extract_ref(&self) -> String {
        self.base.clone()
    }

    fn shared(&self) -> &StackShared {
        &self.shared
    }

    #[doc= "Get a reference to the value of field `allowed_uses` after provisioning.\nList of key usages allowed for the issued certificate. Values are defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and combine flags defined by both [Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) and [Extended Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12). Accepted values: `any_extended`, `cert_signing`, `client_auth`, `code_signing`, `content_commitment`, `crl_signing`, `data_encipherment`, `decipher_only`, `digital_signature`, `email_protection`, `encipher_only`, `ipsec_end_system`, `ipsec_tunnel`, `ipsec_user`, `key_agreement`, `key_encipherment`, `microsoft_commercial_code_signing`, `microsoft_kernel_code_signing`, `microsoft_server_gated_crypto`, `netscape_server_gated_crypto`, `ocsp_signing`, `server_auth`, `timestamping`."]
    pub fn allowed_uses(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.allowed_uses", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_cert_pem` after provisioning.\nCertificate data of the Certificate Authority (CA) in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn ca_cert_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_cert_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_key_algorithm` after provisioning.\nName of the algorithm used when generating the private key provided in `ca_private_key_pem`. "]
    pub fn ca_key_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_key_algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ca_private_key_pem` after provisioning.\nPrivate key of the Certificate Authority (CA) used to sign the certificate, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn ca_private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ca_private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `cert_pem` after provisioning.\nCertificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn cert_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `cert_request_pem` after provisioning.\nCertificate request data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn cert_request_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_request_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `early_renewal_hours` after provisioning.\nThe resource will consider the certificate to have expired the given number of hours before its actual expiry time. This can be useful to deploy an updated certificate in advance of the expiration of the current certificate. However, the old certificate remains valid until its true expiration time, since this resource does not (and cannot) support certificate revocation. Also, this advance update can only be performed should the Terraform configuration be applied during the early renewal period. (default: `0`)"]
    pub fn early_renewal_hours(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.early_renewal_hours", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: the certificate serial number."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `is_ca_certificate` after provisioning.\nIs the generated certificate representing a Certificate Authority (CA) (default: `false`)."]
    pub fn is_ca_certificate(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.is_ca_certificate", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ready_for_renewal` after provisioning.\nIs the certificate either expired (i.e. beyond the `validity_period_hours`) or ready for an early renewal (i.e. within the `early_renewal_hours`)?"]
    pub fn ready_for_renewal(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.ready_for_renewal", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `set_subject_key_id` after provisioning.\nShould the generated certificate include a [subject key identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2) (default: `false`)."]
    pub fn set_subject_key_id(&self) -> PrimExpr<bool> {
        PrimExpr::new(self.shared().clone(), format!("{}.set_subject_key_id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_end_time` after provisioning.\nThe time until which the certificate is invalid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp."]
    pub fn validity_end_time(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_end_time", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_period_hours` after provisioning.\nNumber of hours, after initial issuing, that the certificate will remain valid for."]
    pub fn validity_period_hours(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_period_hours", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `validity_start_time` after provisioning.\nThe time after which the certificate is valid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp."]
    pub fn validity_start_time(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.validity_start_time", self.extract_ref()))
    }
}
