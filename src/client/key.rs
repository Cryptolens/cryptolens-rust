use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::STANDARD};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::{Error, Timestamp, client::TokenizedParams};

use super::{Client, Result};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseKey {
    #[serde(alias = "ProductId")]
    pub product_id: u64,
    #[serde(alias = "Id")]
    pub id: Option<u64>,
    #[serde(alias = "Key")]
    pub key: Option<String>,
    #[serde(alias = "Created")]
    pub created: Timestamp,
    #[serde(alias = "Expires")]
    pub expires: Timestamp,
    #[serde(alias = "Period")]
    pub period: u64,
    #[serde(alias = "F1", alias = "f1")]
    pub feature1: bool,
    #[serde(alias = "F2", alias = "f2")]
    pub feature2: bool,
    #[serde(alias = "F3", alias = "f3")]
    pub feature3: bool,
    #[serde(alias = "F4", alias = "f4")]
    pub feature4: bool,
    #[serde(alias = "F5", alias = "f5")]
    pub feature5: bool,
    #[serde(alias = "F6", alias = "f6")]
    pub feature6: bool,
    #[serde(alias = "F7", alias = "f7")]
    pub feature7: bool,
    #[serde(alias = "F8", alias = "f8")]
    pub feature8: bool,
    #[serde(alias = "Notes")]
    pub notes: Option<String>,
    #[serde(alias = "Block")]
    pub block: bool,
    #[serde(alias = "GlobalId")]
    pub global_id: Option<u64>,
    #[serde(alias = "Customer")]
    pub customer: Option<Customer>,
    #[serde(alias = "ActivatedMachines")]
    pub activated_machines: Vec<ActivatedMachine>,
    #[serde(alias = "TrialActivation")]
    pub trial_activation: bool,
    #[serde(alias = "MaxNoOfMachines")]
    pub max_no_of_machines: Option<i64>,
    #[serde(alias = "AllowedMachines")]
    pub allowed_machines: Option<String>,
    #[serde(alias = "DataObjects")]
    pub data_objects: Vec<DataObject>,
    #[serde(alias = "SignDate")]
    pub sign_date: Timestamp,
    #[serde(alias = "Signature")]
    pub signature: Option<String>,

    #[serde(skip, default)]
    license_key_bytes: Vec<u8>,
    #[serde(skip, default)]
    signature_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivatedMachine {
    #[serde(alias = "Mid")]
    pub mid: String,
    #[serde(alias = "IP")]
    pub ip: IpAddr,
    #[serde(alias = "Time")]
    pub time: Timestamp,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Customer {
    #[serde(alias = "Id")]
    pub id: u64,
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "Email")]
    pub email: String,
    #[serde(alias = "CompanyName")]
    pub company_name: String,
    #[serde(alias = "Created")]
    pub created: Timestamp,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataObject {
    #[serde(alias = "Id")]
    pub id: u64,
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "StringValue")]
    pub string_value: String,
    #[serde(alias = "IntValue")]
    pub int_value: u32,
}

pub type IntervalInSecs = u64;

#[derive(Debug, Clone, Serialize, Builder)]
#[serde(rename_all = "PascalCase")]
#[builder(build_fn(error = "Error"))]
pub struct KeyActivateParams {
    #[builder(setter(into))]
    pub product_id: u64,
    #[builder(setter(into))]
    pub key: String,
    #[builder(setter(into, strip_option), default)]
    pub sign: Option<bool>,
    #[builder(setter(into, strip_option), default)]
    pub machine_code: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub friendly_name: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub fields_to_return: Option<u64>,
    #[builder(setter(skip), default = 1)]
    sign_method: u64,
    #[builder(setter(into, strip_option), default)]
    pub metadata: Option<bool>,
    #[builder(setter(into, strip_option), default)]
    pub floating_time_interval: Option<IntervalInSecs>,
    #[builder(setter(into, strip_option), default)]
    pub max_overdraft: Option<u64>,
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "OSInfo")]
    pub os_info: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub model_version: Option<u64>,
    #[serde(rename = "v")]
    #[builder(setter(into, strip_option), default)]
    pub method_version: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RsaKeyValue {
    pub modulus: String,
    pub exponent: String,
}

pub type PublicKey = openssl::pkey::PKey<openssl::pkey::Public>;

impl Client {
    pub async fn key_activate(
        &self,
        token: impl AsRef<str>,
        params: KeyActivateParams,
    ) -> Result<LicenseKey> {
        let params = TokenizedParams {
            token: token.as_ref(),
            params,
        };
        let res: KeyActivateResponse = self
            .client
            .post("https://app.cryptolens.io/api/key/Activate")
            .form(&params)
            .send()
            .await?
            .json()
            .await?;

        res.try_into()
    }
}

impl LicenseKey {
    pub fn has_valid_signature(
        &self,
        public_key: impl TryInto<PublicKey, Error = Error>,
    ) -> Result<bool> {
        let public_key: PublicKey = public_key.try_into()?;

        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key)?;

        verifier.update(&self.license_key_bytes)?;
        Ok(verifier.verify(&self.signature_bytes)?)
    }
}

impl TryFrom<KeyActivateResponse> for LicenseKey {
    type Error = Error;

    fn try_from(value: KeyActivateResponse) -> Result<Self> {
        if value.result == 1 {
            return Err(Error::Api(value.message));
        };
        Ok(
            match value.license_key.ok_or_else(|| {
                Error::Custom("licenseKey field is required for success result".to_string())
            })? {
                LicenseKeyResponse::Json(license_key) => license_key,
                LicenseKeyResponse::Base64(encoded) => {
                    let license_key_bytes = STANDARD.decode(encoded)?;
                    let mut license_key: LicenseKey = serde_json::from_slice(&license_key_bytes)?;
                    license_key.license_key_bytes = license_key_bytes;
                    license_key.signature_bytes =
                        STANDARD.decode(value.signature.unwrap_or_default())?;
                    license_key
                }
            },
        )
    }
}

impl RsaKeyValue {
    pub fn from_xml_str(input: &str) -> Result<Self> {
        Ok(serde_xml_rs::from_str(input)?)
    }
}

impl TryFrom<RsaKeyValue> for PublicKey {
    type Error = Error;

    fn try_from(value: RsaKeyValue) -> std::result::Result<Self, Self::Error> {
        let modulus_decoded = STANDARD.decode(&value.modulus)?;
        let exponent_decoded = STANDARD.decode(&value.exponent)?;

        let modulus = openssl::bn::BigNum::from_slice(&modulus_decoded)?;
        let exponent = openssl::bn::BigNum::from_slice(&exponent_decoded)?;

        let keypair = openssl::rsa::Rsa::from_public_components(modulus, exponent)?;
        Ok(openssl::pkey::PKey::from_rsa(keypair)?)
    }
}

impl KeyActivateParams {
    pub fn builder() -> KeyActivateParamsBuilder {
        KeyActivateParamsBuilder::default()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyActivateResponse {
    license_key: Option<LicenseKeyResponse>,
    signature: Option<String>,
    result: u8,
    message: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
enum LicenseKeyResponse {
    Json(LicenseKey),
    Base64(String),
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_deser_if_sign_method_one() {
        // given
        let input = r#"{"licenseKey":"eyJQcm9kdWN0SWQiOjMsIklEIjo2LCJLZXkiOiJHT1hHWi1WQUNLRS1TUUJZRS1CUlhVUCIsIkNyZWF0ZWQiOiIyMDE0LTAxLTAyVDAwOjAwOjAwIiwiRXhwaXJlcyI6IjIwMTQtMDItMTZUMDA6MDA6MDAiLCJQZXJpb2QiOjQ1LCJGMSI6dHJ1ZSwiRjIiOnRydWUsIkYzIjpmYWxzZSwiRjQiOmZhbHNlLCJGNSI6ZmFsc2UsIkY2IjpmYWxzZSwiRjciOmZhbHNlLCJGOCI6ZmFsc2UsIk5vdGVzIjoidG8gU2NvdCIsIkJsb2NrIjpmYWxzZSwiR2xvYmFsSWQiOjEwMDksIkN1c3RvbWVyIjp7IklkIjoyNywiTmFtZSI6ImN1c3RvbWVyIiwiRW1haWwiOiJhcnRlbUBhcnRlbWxvcy5uZXQiLCJDb21wYW55TmFtZSI6InRlc3QiLCJDcmVhdGVkIjoiMjAxNi0wMS0wNFQxOTo0OTowOS4zMDcifSwiQWN0aXZhdGVkTWFjaGluZXMiOltdLCJUcmlhbEFjdGl2YXRpb24iOmZhbHNlLCJNYXhOb09mTWFjaGluZXMiOi0xLCJBbGxvd2VkTWFjaGluZXMiOm51bGwsIkRhdGFPYmplY3RzIjpbXSwiU2lnbkRhdGUiOiIyMDE3LTA0LTE0VDE0OjE1OjM4IiwiU2lnbmF0dXJlIjpudWxsfQ==","signature":"fVhV2revZTug1HtYcLkSEEMCPk0AkaBWBl4cRYOXlOpHR5S7xNtcY9o+wXRuauNXzGXh5LQcT8Ybo1HJ1LFp3z7sEfoDZZHfckbKbeSOTi+ercuqH26nWdvD2wgKsJsU0Rx6iClyKezNS36azriubdxcVabClFawn65GHexw14AeQlGU1jreAs0N57Dw/jwuBPXGfId64V8daOozVJQFhJVA6B1ZSu01FfxuBQxn2kj+UhjRGMp79JasCu2h1V5End66IHf0jlbgfsRDlWGfik1oK1LhFfkVV9rURSWiINhh1rZn1NM4ELHr/ASXUj1P1PdrtPadobDO+eXDUZhBHQ==","result":0,"message":""}"#;

        // when
        let parsed = serde_json::from_str::<KeyActivateResponse>(input);

        // then
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_deser_error() {
        // given
        let input = r#"{"result":1,"message":"Unable to authenticate."}"#;

        // when
        let parsed: Result<LicenseKey> = serde_json::from_str::<KeyActivateResponse>(input)
            .unwrap()
            .try_into();

        // then
        assert!(
            matches!(parsed, Err(Error::Api(message)) if message.eq("Unable to authenticate."))
        );
    }

    #[test]
    fn test_key_activate_params_ser_minimal() {
        // given
        let params = KeyActivateParams::builder()
            .product_id(1u64)
            .key("key")
            .build()
            .unwrap();

        let params = TokenizedParams {
            token: "TOKEN",
            params,
        };

        // when
        let url = serde_urlencoded::to_string(&params);

        // then
        assert_eq!(
            url,
            Ok("token=TOKEN&ProductId=1&Key=key&SignMethod=1".to_string())
        );
    }

    #[test]
    fn test_key_activate_params_ser() {
        // given
        let params = KeyActivateParams::builder()
            .product_id(1u64)
            .key("key")
            .sign(true)
            .max_overdraft(4u64)
            .machine_code("code")
            .build()
            .unwrap();

        let params = TokenizedParams {
            token: "TOKEN",
            params,
        };

        // when
        let url = serde_urlencoded::to_string(&params);

        // then
        assert_eq!(
            url,
            Ok(
                "token=TOKEN&ProductId=1&Key=key&Sign=true&MachineCode=code&SignMethod=1&MaxOverdraft=4"
                    .to_string()
            )
        );
    }
}
