# Cryptolens Client API for Rust

> This library is currently in a beta release.

This library simplifies access to the [Cryptolens Web API](https://cryptolens.io) from the
Rust programming language.

Several examples are available in the [`examples/`](examples/) directory of this repository.

## Examples

### Activate a license key

The [`activate`](examples/activate.rs) example activates a license key with `sign(true)` and verifies the signed response with your Cryptolens public key:

```rust
use cryptolens::{Client, KeyActivateParams, RsaKeyValue};

#[tokio::main]
async fn main() {
    let client = Client::default();

    let params = KeyActivateParams::builder()
        .product_id(3646u64)
        .key("MPDWY-PQAOW-FKSCH-SGAAU")
        .machine_code("289jf2afs3")
        .sign(true)
        .build()
        .unwrap();

    let token = "YOUR_ACCESS_TOKEN";
    let license_key = client.key_activate(token, params).await.unwrap();

    let public_key = r#"<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"#;
    let public_key = RsaKeyValue::from_xml_str(public_key).unwrap();

    match license_key.has_valid_signature(public_key) {
        Ok(true) => {
            println!("Successfully activated license key: {}", license_key.key.unwrap());
        }
        _ => {
            println!("Signature check failed. Aborting!");
        }
    }
}
```

### Load from string for offline verification

The [`from_str`](examples/from_str.rs) example shows how to deserialize a previously saved activation response string and verify it offline:

```rust
use cryptolens::{KeyActivateResponse, LicenseKey, RsaKeyValue};

fn main() {
    let saved_response = r#"{"licenseKey":"...","signature":"...","result":0,"message":""}"#;

    let key_activate_response: KeyActivateResponse =
        serde_json::from_str(saved_response).unwrap();
    let license_key: LicenseKey = key_activate_response.try_into().unwrap();

    let public_key = r#"<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"#;
    let public_key = RsaKeyValue::from_xml_str(public_key).unwrap();

    match license_key.has_valid_signature(public_key) {
        Ok(true) => {
            println!("Successfully loaded license key: {}", license_key.key.unwrap());
        }
        _ => {
            println!("Signature check failed. Aborting!");
        }
    }
}
```

As long as the library is at version `0.0.X` we are not following semantic versioning. Before
moving to version `0.1.0` at least the following needs to be implemented:

 * [ ] Parse server message when an activation fails, and return an appropriate error.
 * [ ] Add proper management of errors in third-party libraries.
 * [ ] Decide on how to deal with time, should we depend on e.g. the `chrono` crate?
       Or should we just expose the time as an integer and let the user deal with this
       as we do now?
 * [ ] Possibly change capitalization of names to make them more rust-like
