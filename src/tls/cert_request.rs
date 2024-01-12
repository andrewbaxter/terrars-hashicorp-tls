use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;
use super::provider::ProviderTls;

#[derive(Serialize)]
struct CertRequestData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "SerdeSkipDefault::is_default")]
    lifecycle: ResourceLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_each: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_names: Option<ListField<PrimField<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_addresses: Option<ListField<PrimField<String>>>,
    private_key_pem: PrimField<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uris: Option<ListField<PrimField<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Vec<CertRequestSubjectEl>>,
    dynamic: CertRequestDynamic,
}

struct CertRequest_ {
    shared: StackShared,
    tf_id: String,
    data: RefCell<CertRequestData>,
}

#[derive(Clone)]
pub struct CertRequest(Rc<CertRequest_>);

impl CertRequest {
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

    #[doc= "Set the field `dns_names`.\nList of DNS names for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn set_dns_names(self, v: impl Into<ListField<PrimField<String>>>) -> Self {
        self.0.data.borrow_mut().dns_names = Some(v.into());
        self
    }

    #[doc= "Set the field `ip_addresses`.\nList of IP addresses for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn set_ip_addresses(self, v: impl Into<ListField<PrimField<String>>>) -> Self {
        self.0.data.borrow_mut().ip_addresses = Some(v.into());
        self
    }

    #[doc= "Set the field `uris`.\nList of URIs for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn set_uris(self, v: impl Into<ListField<PrimField<String>>>) -> Self {
        self.0.data.borrow_mut().uris = Some(v.into());
        self
    }

    #[doc= "Set the field `subject`.\n"]
    pub fn set_subject(self, v: impl Into<BlockAssignable<CertRequestSubjectEl>>) -> Self {
        match v.into() {
            BlockAssignable::Literal(v) => {
                self.0.data.borrow_mut().subject = Some(v);
            },
            BlockAssignable::Dynamic(d) => {
                self.0.data.borrow_mut().dynamic.subject = Some(d);
            },
        }
        self
    }

    #[doc= "Get a reference to the value of field `cert_request_pem` after provisioning.\nThe certificate request data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn cert_request_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_request_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `dns_names` after provisioning.\nList of DNS names for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn dns_names(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.dns_names", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: hexadecimal representation of the SHA1 checksum of the resource."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ip_addresses` after provisioning.\nList of IP addresses for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn ip_addresses(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.ip_addresses", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `key_algorithm` after provisioning.\nName of the algorithm used when generating the private key provided in `private_key_pem`. "]
    pub fn key_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.key_algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nPrivate key in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, that the certificate will belong to. This can be read from a separate file using the [`file`](https://www.terraform.io/language/functions/file) interpolation function. Only an irreversible secure hash of the private key will be stored in the Terraform state."]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `uris` after provisioning.\nList of URIs for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn uris(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.uris", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `subject` after provisioning.\n"]
    pub fn subject(&self) -> ListRef<CertRequestSubjectElRef> {
        ListRef::new(self.shared().clone(), format!("{}.subject", self.extract_ref()))
    }
}

impl Referable for CertRequest {
    fn extract_ref(&self) -> String {
        format!("{}.{}", self.0.extract_resource_type(), self.0.extract_tf_id())
    }
}

impl Resource for CertRequest { }

impl ToListMappable for CertRequest {
    type O = ListRef<CertRequestRef>;

    fn do_map(self, base: String) -> Self::O {
        self.0.data.borrow_mut().for_each = Some(format!("${{{}}}", base));
        ListRef::new(self.0.shared.clone(), self.extract_ref())
    }
}

impl Resource_ for CertRequest_ {
    fn extract_resource_type(&self) -> String {
        "tls_cert_request".into()
    }

    fn extract_tf_id(&self) -> String {
        self.tf_id.clone()
    }

    fn extract_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildCertRequest {
    pub tf_id: String,
    #[doc= "Private key in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, that the certificate will belong to. This can be read from a separate file using the [`file`](https://www.terraform.io/language/functions/file) interpolation function. Only an irreversible secure hash of the private key will be stored in the Terraform state."]
    pub private_key_pem: PrimField<String>,
}

impl BuildCertRequest {
    pub fn build(self, stack: &mut Stack) -> CertRequest {
        let out = CertRequest(Rc::new(CertRequest_ {
            shared: stack.shared.clone(),
            tf_id: self.tf_id,
            data: RefCell::new(CertRequestData {
                depends_on: core::default::Default::default(),
                provider: None,
                lifecycle: core::default::Default::default(),
                for_each: None,
                dns_names: core::default::Default::default(),
                ip_addresses: core::default::Default::default(),
                private_key_pem: self.private_key_pem,
                uris: core::default::Default::default(),
                subject: core::default::Default::default(),
                dynamic: Default::default(),
            }),
        }));
        stack.add_resource(out.0.clone());
        out
    }
}

pub struct CertRequestRef {
    shared: StackShared,
    base: String,
}

impl Ref for CertRequestRef {
    fn new(shared: StackShared, base: String) -> Self {
        Self {
            shared: shared,
            base: base,
        }
    }
}

impl CertRequestRef {
    fn extract_ref(&self) -> String {
        self.base.clone()
    }

    fn shared(&self) -> &StackShared {
        &self.shared
    }

    #[doc= "Get a reference to the value of field `cert_request_pem` after provisioning.\nThe certificate request data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn cert_request_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.cert_request_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `dns_names` after provisioning.\nList of DNS names for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn dns_names(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.dns_names", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: hexadecimal representation of the SHA1 checksum of the resource."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ip_addresses` after provisioning.\nList of IP addresses for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn ip_addresses(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.ip_addresses", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `key_algorithm` after provisioning.\nName of the algorithm used when generating the private key provided in `private_key_pem`. "]
    pub fn key_algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.key_algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nPrivate key in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, that the certificate will belong to. This can be read from a separate file using the [`file`](https://www.terraform.io/language/functions/file) interpolation function. Only an irreversible secure hash of the private key will be stored in the Terraform state."]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `uris` after provisioning.\nList of URIs for which a certificate is being requested (i.e. certificate subjects)."]
    pub fn uris(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.uris", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `subject` after provisioning.\n"]
    pub fn subject(&self) -> ListRef<CertRequestSubjectElRef> {
        ListRef::new(self.shared().clone(), format!("{}.subject", self.extract_ref()))
    }
}

#[derive(Serialize)]
pub struct CertRequestSubjectEl {
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organizational_unit: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    province: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_number: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    street_address: Option<ListField<PrimField<String>>>,
}

impl CertRequestSubjectEl {
    #[doc= "Set the field `common_name`.\nDistinguished name: `CN`"]
    pub fn set_common_name(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.common_name = Some(v.into());
        self
    }

    #[doc= "Set the field `country`.\nDistinguished name: `C`"]
    pub fn set_country(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.country = Some(v.into());
        self
    }

    #[doc= "Set the field `locality`.\nDistinguished name: `L`"]
    pub fn set_locality(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.locality = Some(v.into());
        self
    }

    #[doc= "Set the field `organization`.\nDistinguished name: `O`"]
    pub fn set_organization(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.organization = Some(v.into());
        self
    }

    #[doc= "Set the field `organizational_unit`.\nDistinguished name: `OU`"]
    pub fn set_organizational_unit(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.organizational_unit = Some(v.into());
        self
    }

    #[doc= "Set the field `postal_code`.\nDistinguished name: `PC`"]
    pub fn set_postal_code(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.postal_code = Some(v.into());
        self
    }

    #[doc= "Set the field `province`.\nDistinguished name: `ST`"]
    pub fn set_province(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.province = Some(v.into());
        self
    }

    #[doc= "Set the field `serial_number`.\nDistinguished name: `SERIALNUMBER`"]
    pub fn set_serial_number(mut self, v: impl Into<PrimField<String>>) -> Self {
        self.serial_number = Some(v.into());
        self
    }

    #[doc= "Set the field `street_address`.\nDistinguished name: `STREET`"]
    pub fn set_street_address(mut self, v: impl Into<ListField<PrimField<String>>>) -> Self {
        self.street_address = Some(v.into());
        self
    }
}

impl ToListMappable for CertRequestSubjectEl {
    type O = BlockAssignable<CertRequestSubjectEl>;

    fn do_map(self, base: String) -> Self::O {
        BlockAssignable::Dynamic(DynamicBlock {
            for_each: format!("${{{}}}", base),
            iterator: "each".into(),
            content: self,
        })
    }
}

pub struct BuildCertRequestSubjectEl {}

impl BuildCertRequestSubjectEl {
    pub fn build(self) -> CertRequestSubjectEl {
        CertRequestSubjectEl {
            common_name: core::default::Default::default(),
            country: core::default::Default::default(),
            locality: core::default::Default::default(),
            organization: core::default::Default::default(),
            organizational_unit: core::default::Default::default(),
            postal_code: core::default::Default::default(),
            province: core::default::Default::default(),
            serial_number: core::default::Default::default(),
            street_address: core::default::Default::default(),
        }
    }
}

pub struct CertRequestSubjectElRef {
    shared: StackShared,
    base: String,
}

impl Ref for CertRequestSubjectElRef {
    fn new(shared: StackShared, base: String) -> CertRequestSubjectElRef {
        CertRequestSubjectElRef {
            shared: shared,
            base: base.to_string(),
        }
    }
}

impl CertRequestSubjectElRef {
    fn shared(&self) -> &StackShared {
        &self.shared
    }

    #[doc= "Get a reference to the value of field `common_name` after provisioning.\nDistinguished name: `CN`"]
    pub fn common_name(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.common_name", self.base))
    }

    #[doc= "Get a reference to the value of field `country` after provisioning.\nDistinguished name: `C`"]
    pub fn country(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.country", self.base))
    }

    #[doc= "Get a reference to the value of field `locality` after provisioning.\nDistinguished name: `L`"]
    pub fn locality(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.locality", self.base))
    }

    #[doc= "Get a reference to the value of field `organization` after provisioning.\nDistinguished name: `O`"]
    pub fn organization(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.organization", self.base))
    }

    #[doc= "Get a reference to the value of field `organizational_unit` after provisioning.\nDistinguished name: `OU`"]
    pub fn organizational_unit(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.organizational_unit", self.base))
    }

    #[doc= "Get a reference to the value of field `postal_code` after provisioning.\nDistinguished name: `PC`"]
    pub fn postal_code(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.postal_code", self.base))
    }

    #[doc= "Get a reference to the value of field `province` after provisioning.\nDistinguished name: `ST`"]
    pub fn province(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.province", self.base))
    }

    #[doc= "Get a reference to the value of field `serial_number` after provisioning.\nDistinguished name: `SERIALNUMBER`"]
    pub fn serial_number(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.serial_number", self.base))
    }

    #[doc= "Get a reference to the value of field `street_address` after provisioning.\nDistinguished name: `STREET`"]
    pub fn street_address(&self) -> ListRef<PrimExpr<String>> {
        ListRef::new(self.shared().clone(), format!("{}.street_address", self.base))
    }
}

#[derive(Serialize, Default)]
struct CertRequestDynamic {
    subject: Option<DynamicBlock<CertRequestSubjectEl>>,
}
