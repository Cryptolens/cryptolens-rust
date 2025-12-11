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

    let token = "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0=";

    let license_key = client.key_activate(token, params).await.unwrap();

    let public_key = r#"<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"#;

    let public_key = RsaKeyValue::from_xml_str(public_key).unwrap();

    match &license_key.has_valid_signature(public_key) {
        Ok(true) => {}
        _ => {
            println!("Signature check failed. Aborting!");
            return;
        }
    }

    println!(
        "Successfully activated license key: {}",
        license_key.key.unwrap()
    );
}
