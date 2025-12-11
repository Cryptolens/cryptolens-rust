use cryptolens::{KeyActivateResponse, LicenseKey, RsaKeyValue};

fn main() {
    let key_activate_response: KeyActivateResponse = serde_json::from_str(
      r#"{"licenseKey":"eyJQcm9kdWN0SWQiOjM2NDYsIklEIjo0LCJLZXkiOiJNUERXWS1QUUFPVy1GS1NDSC1TR0FBVSIsIkNyZWF0ZWQiOjE0OTAzMTM2MDAsIkV4cGlyZXMiOjI0MDA3NTU1OTUsIlBlcmlvZCI6MTAwMDAsIkYxIjpmYWxzZSwiRjIiOmZhbHNlLCJGMyI6ZmFsc2UsIkY0IjpmYWxzZSwiRjUiOmZhbHNlLCJGNiI6ZmFsc2UsIkY3IjpmYWxzZSwiRjgiOmZhbHNlLCJOb3RlcyI6bnVsbCwiQmxvY2siOmZhbHNlLCJHbG9iYWxJZCI6MzE4NzYsIkN1c3RvbWVyIjpudWxsLCJBY3RpdmF0ZWRNYWNoaW5lcyI6W3siTWlkIjoiMjg5amYyYWZzMyIsIklQIjoiMTU4LjE3NC4xODYuNDgiLCJUaW1lIjoxNjEyOTY2MDc2fSx7Ik1pZCI6InRlc3QxMjMiLCJJUCI6IjE1OC4xNzQuMjMuMjI3IiwiVGltZSI6MTY2MTg0MjExOH1dLCJUcmlhbEFjdGl2YXRpb24iOmZhbHNlLCJNYXhOb09mTWFjaGluZXMiOjIsIkFsbG93ZWRNYWNoaW5lcyI6IiIsIkRhdGFPYmplY3RzIjpbXSwiU2lnbkRhdGUiOjE3NjU0NDU2MzF9","signature":"hX7EZByB0/444Sriiub+3gI2KdULyfqXE7w7rwrn+AiR2bG7WvIhPatpphVpxfRXPEPCgpdNU0IbdHCrHTb8qR312NUoX6k3pDnwgAkaFqNqqY+NVhqw9R9H46056z50vqOMza1g60bWTlCwGCsrmODfu7sRAeymqOHahlLS0spz3Jm7Xlitsk30kkJdG32tM356J4LVG1FS8YYysH1xoQxdf6TldJa9GnxaIa37IarUFnC7t+q81fgI7Wnxa3ySV7u6M0Ec6tFlOVBXJ5vbCTvyR6enDfAC2HPXxbOFYPg8T1zpwsxzy4ho5M3lJuAyf/Z5B65hiop9u1TvQ9dVGA==","result":0,"message":""}"#
    ).unwrap();

    let license_key: LicenseKey = key_activate_response.try_into().unwrap();

    let public_key = r#"<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"#;

    let public_key = RsaKeyValue::from_xml_str(public_key).unwrap();

    match license_key.has_valid_signature(public_key) {
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
