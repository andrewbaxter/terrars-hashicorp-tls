use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;
use terrars::*;
use super::provider::ProviderTls;

#[derive(Serialize)]
struct DataPublicKeyData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    #[serde(skip_serializing_if = "SerdeSkipDefault::is_default")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_each: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_openssh: Option<PrimField<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<PrimField<String>>,
}

struct DataPublicKey_ {
    shared: StackShared,
    tf_id: String,
    data: RefCell<DataPublicKeyData>,
}

#[derive(Clone)]
pub struct DataPublicKey(Rc<DataPublicKey_>);

impl DataPublicKey {
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

    #[doc= "Set the field `private_key_openssh`.\nThe private key (in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) to extract the public key from. This is _mutually exclusive_ with `private_key_pem`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn set_private_key_openssh(self, v: impl Into<PrimField<String>>) -> Self {
        self.0.data.borrow_mut().private_key_openssh = Some(v.into());
        self
    }

    #[doc= "Set the field `private_key_pem`.\nThe private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) to extract the public key from. This is _mutually exclusive_ with `private_key_openssh`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn set_private_key_pem(self, v: impl Into<PrimField<String>>) -> Self {
        self.0.data.borrow_mut().private_key_pem = Some(v.into());
        self
    }

    #[doc= "Get a reference to the value of field `algorithm` after provisioning.\nThe name of the algorithm used by the given private key. Possible values are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this data source: hexadecimal representation of the SHA1 checksum of the data source."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_openssh` after provisioning.\nThe private key (in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) to extract the public key from. This is _mutually exclusive_ with `private_key_pem`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn private_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nThe private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) to extract the public key from. This is _mutually exclusive_ with `private_key_openssh`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_md5` after provisioning.\nThe fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_md5(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_md5", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_sha256` after provisioning.\nThe fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_sha256(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_sha256", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_openssh` after provisioning.\nThe public key, in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format. This is also known as ['Authorized Keys'](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_pem` after provisioning.\nThe public key, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_pem", self.extract_ref()))
    }
}

impl Referable for DataPublicKey {
    fn extract_ref(&self) -> String {
        format!("data.{}.{}", self.0.extract_datasource_type(), self.0.extract_tf_id())
    }
}

impl Datasource for DataPublicKey { }

impl ToListMappable for DataPublicKey {
    type O = ListRef<DataPublicKeyRef>;

    fn do_map(self, base: String) -> Self::O {
        self.0.data.borrow_mut().for_each = Some(format!("${{{}}}", base));
        ListRef::new(self.0.shared.clone(), self.extract_ref())
    }
}

impl Datasource_ for DataPublicKey_ {
    fn extract_datasource_type(&self) -> String {
        "tls_public_key".into()
    }

    fn extract_tf_id(&self) -> String {
        self.tf_id.clone()
    }

    fn extract_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.data).unwrap()
    }
}

pub struct BuildDataPublicKey {
    pub tf_id: String,
}

impl BuildDataPublicKey {
    pub fn build(self, stack: &mut Stack) -> DataPublicKey {
        let out = DataPublicKey(Rc::new(DataPublicKey_ {
            shared: stack.shared.clone(),
            tf_id: self.tf_id,
            data: RefCell::new(DataPublicKeyData {
                depends_on: core::default::Default::default(),
                provider: None,
                for_each: None,
                private_key_openssh: core::default::Default::default(),
                private_key_pem: core::default::Default::default(),
            }),
        }));
        stack.add_datasource(out.0.clone());
        out
    }
}

pub struct DataPublicKeyRef {
    shared: StackShared,
    base: String,
}

impl Ref for DataPublicKeyRef {
    fn new(shared: StackShared, base: String) -> Self {
        Self {
            shared: shared,
            base: base,
        }
    }
}

impl DataPublicKeyRef {
    fn shared(&self) -> &StackShared {
        &self.shared
    }

    fn extract_ref(&self) -> String {
        self.base.clone()
    }

    #[doc= "Get a reference to the value of field `algorithm` after provisioning.\nThe name of the algorithm used by the given private key. Possible values are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn algorithm(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.algorithm", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `id` after provisioning.\nUnique identifier for this data source: hexadecimal representation of the SHA1 checksum of the data source."]
    pub fn id(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.id", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_openssh` after provisioning.\nThe private key (in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) to extract the public key from. This is _mutually exclusive_ with `private_key_pem`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn private_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `private_key_pem` after provisioning.\nThe private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) to extract the public key from. This is _mutually exclusive_ with `private_key_openssh`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`. "]
    pub fn private_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.private_key_pem", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_md5` after provisioning.\nThe fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_md5(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_md5", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_fingerprint_sha256` after provisioning.\nThe fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations)."]
    pub fn public_key_fingerprint_sha256(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_fingerprint_sha256", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_openssh` after provisioning.\nThe public key, in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format. This is also known as ['Authorized Keys'](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_openssh(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_openssh", self.extract_ref()))
    }

    #[doc= "Get a reference to the value of field `public_key_pem` after provisioning.\nThe public key, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace)."]
    pub fn public_key_pem(&self) -> PrimExpr<String> {
        PrimExpr::new(self.shared().clone(), format!("{}.public_key_pem", self.extract_ref()))
    }
}
