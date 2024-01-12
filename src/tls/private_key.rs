use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;
use super::provider::ProviderTls;

#[derive(Serialize)]
struct PrivateKeyData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "SerdeSkipDefault::is_default")]
    lifecycle: ResourceLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_each: Option<String>,
    algorithm: PrimField<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecdsa_curve: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rsa_bits: Option<PrimField<f64>>,
}

struct PrivateKey_ {
    shared: StackShared,
    tf_id: String,
    data: RefCell<PrivateKeyData>,
}

#[derive(Clone)]
pub struct PrivateKey(Rc<PrivateKey_>);

impl PrivateKey {
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

    #[doc= "Set the field `ecdsa_curve`.\nWhen `algorithm` is `ECDSA`, the name of the elliptic curve to use. Currently-supported values are: `P224`, `P256`, `P384`, `P521`. (default: `P224`)."]
    pub fn set_ecdsa_curve(self, v: impl Into<PrimField<String>>) -> Self {
        self.0.data.borrow_mut().ecdsa_curve = Some(v.into());
        self
    }

    #[doc= "Set the field `rsa_bits`.\nWhen `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`)."]
    pub fn set_rsa_bits(self, v: impl Into<PrimField<f64>>) -> Self {
        self.0.data.borrow_mut().rsa_bits = Some(v.into());
        self
    }

    #[doc= "Get a reference to the value of field `algorithm` after provisioning.\nName of the algorithm to use when generating the private key. Currently-supported values are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ecdsa_curve` after provisioning.\nWhen `algorithm` is `ECDSA`, the name of the elliptic curve to use. Currently-supported values are: `P224`, `P256`, `P384`, `P521`. (default: `P224`)."]
    pub fn ecdsa_curve(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ecdsa_curve", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: hexadecimal representation of the SHA1 checksum of the resource."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_openssh` after provisioning.\nPrivate key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format."]
    pub fn private_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nPrivate key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem_pkcs8` after provisioning.\nPrivate key data in [PKCS#8 PEM (RFC 5208)](https://datatracker.ietf.org/doc/html/rfc5208) format."]
    pub fn private_key_pem_pkcs8(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem_pkcs8", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_md5` after provisioning.\nThe fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the selected private key format is compatible, similarly to `public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_md5(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_md5", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_sha256` after provisioning.\nThe fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the selected private key format is compatible, similarly to `public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_sha256(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_sha256", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_openssh` after provisioning.\n The public key data in [\"Authorized Keys\"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_pem` after provisioning.\nPublic key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `rsa_bits` after provisioning.\nWhen `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`)."]
    pub fn rsa_bits(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.rsa_bits", self.extract_ref()))
    }
}

impl Referable for PrivateKey {
    fn extract_ref(&self) -> String {
        format!("{}.{}", self.0.extract_resource_type(), self.0.extract_tf_id())
    }
}

impl Resource for PrivateKey { }

impl ToListMappable for PrivateKey {
    type O = ListRef<PrivateKeyRef>;

    fn do_map(self, base: String) -> Self::O {
        self.0.data.borrow_mut().for_each = Some(format!("${{{}}}", base));
        ListRef::new(self.0.shared.clone(), self.extract_ref())
    }
}

impl Resource_ for PrivateKey_ {
    fn extract_resource_type(&self) -> String {
        "tls_private_key".into()
    }

    fn extract_tf_id(&self) -> String {
        self.tf_id.clone()
    }

    fn extract_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildPrivateKey {
    pub tf_id: String,
    #[doc= "Name of the algorithm to use when generating the private key. Currently-supported values are: `RSA`, `ECDSA`, `ED25519`. "]
    pub algorithm: PrimField<String>,
}

impl BuildPrivateKey {
    pub fn build(self, stack: &mut Stack) -> PrivateKey {
        let out = PrivateKey(Rc::new(PrivateKey_ {
            shared: stack.shared.clone(),
            tf_id: self.tf_id,
            data: RefCell::new(PrivateKeyData {
                depends_on: core::default::Default::default(),
                provider: None,
                lifecycle: core::default::Default::default(),
                for_each: None,
                algorithm: self.algorithm,
                ecdsa_curve: core::default::Default::default(),
                rsa_bits: core::default::Default::default(),
            }),
        }));
        stack.add_resource(out.0.clone());
        out
    }
}

pub struct PrivateKeyRef {
    shared: StackShared,
    base: String,
}

impl Ref for PrivateKeyRef {
    fn new(shared: StackShared, base: String) -> Self {
        Self {
            shared: shared,
            base: base,
        }
    }
}

impl PrivateKeyRef {
    fn extract_ref(&self) -> String {
        self.base.clone()
    }

    fn shared(&self) -> &StackShared {
        &self.shared
    }

    #[doc= "Get a reference to the value of field `algorithm` after provisioning.\nName of the algorithm to use when generating the private key. Currently-supported values are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `ecdsa_curve` after provisioning.\nWhen `algorithm` is `ECDSA`, the name of the elliptic curve to use. Currently-supported values are: `P224`, `P256`, `P384`, `P521`. (default: `P224`)."]
    pub fn ecdsa_curve(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.ecdsa_curve", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this resource: hexadecimal representation of the SHA1 checksum of the resource."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_openssh` after provisioning.\nPrivate key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format."]
    pub fn private_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nPrivate key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format."]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem_pkcs8` after provisioning.\nPrivate key data in [PKCS#8 PEM (RFC 5208)](https://datatracker.ietf.org/doc/html/rfc5208) format."]
    pub fn private_key_pem_pkcs8(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem_pkcs8", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_md5` after provisioning.\nThe fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the selected private key format is compatible, similarly to `public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_md5(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_md5", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_sha256` after provisioning.\nThe fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the selected private key format is compatible, similarly to `public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_sha256(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_sha256", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_openssh` after provisioning.\n The public key data in [\"Authorized Keys\"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_pem` after provisioning.\nPublic key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `rsa_bits` after provisioning.\nWhen `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`)."]
    pub fn rsa_bits(&self) -> PrimExpr<f64> {
        PrimExpr::new(self.shared().clone(), format!("{}.rsa_bits", self.extract_ref()))
    }
}
