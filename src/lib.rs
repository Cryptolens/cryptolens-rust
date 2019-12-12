use std::result::Result;

use serde::{Deserialize, Serialize};
//use serde_json::Result;

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ActivateResponse {
  result: i64,
  message: Option<String>,
  licenseKey: Option<String>,
  signature: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct SerdeLicenseKey {
  ProductId: u64,
  Id: Option<u64>,
  Key: Option<String>,
  Created: u64,
  Expires: u64,
  Period: u64,
  F1: bool,
  F2: bool,
  F3: bool,
  F4: bool,
  F5: bool,
  F6: bool,
  F7: bool,
  F8: bool,
  Notes: Option<String>,
  Block: bool,
  GlobalId: Option<u64>,
  Customer: Option<Customer>,
  ActivatedMachines: Vec<ActivationData>,
  TrialActivation: bool,
  MaxNoOfMachines: Option<u64>,
  AllowedMachines: String,
  DataObjects: Vec<DataObject>,
  SignDate: u64,
}

#[allow(non_snake_case)]
pub struct LicenseKey {
  pub ProductId: u64,
  pub Id: Option<u64>,
  pub Key: Option<String>,
  pub Created: u64,
  pub Expires: u64,
  pub Period: u64,
  pub F1: bool,
  pub F2: bool,
  pub F3: bool,
  pub F4: bool,
  pub F5: bool,
  pub F6: bool,
  pub F7: bool,
  pub F8: bool,
  pub Notes: Option<String>,
  pub Block: bool,
  pub GlobalId: Option<u64>,
  pub Customer: Option<Customer>,
  pub ActivatedMachines: Vec<ActivationData>,
  pub TrialActivation: bool,
  pub MaxNoOfMachines: Option<u64>,
  pub AllowedMachines: Vec<String>,
  pub DataObjects: Vec<DataObject>,
  pub SignDate: u64,

  license_key_bytes: Vec<u8>,
  signature_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Customer {
  pub Id: u64,
  pub Name: String,
  pub Email: String,
  pub CompanyName: String,
  pub Created: u64,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ActivationData {
  pub Mid: String,
  pub IP: String,
  pub Time: u64,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct DataObject {
  pub Id: u64,
  pub Name: String,
  pub StringValue: String,
  pub IntValue: u64,
}

#[allow(non_snake_case)]
pub struct KeyActivateArguments<'a, 'b> {
  pub ProductId: u64,
  pub Key: &'a str,
  pub MachineCode: &'b str,
  pub FieldsToReturn: u64,
  pub FloatingTimeInterval: u64,
  pub MaxOverdraft: u64,
}

impl Default for KeyActivateArguments<'static, 'static> {
  fn default() -> Self {
    KeyActivateArguments {
      ProductId: 0,
      Key: "",
      MachineCode: "",
      FieldsToReturn: 0,
      FloatingTimeInterval: 0,
      MaxOverdraft: 0,
    }
  }
}

impl LicenseKey {
  pub fn from_str(s: &str) -> Result<LicenseKey, ()> {
    let activate_response: ActivateResponse = serde_json::from_str(&s).map_err(|_| ())?;

    // TODO: Check result and parse message in case there is an error

    let license_key: &str = activate_response.licenseKey.as_ref().ok_or(())?;
    let signature: &str = activate_response.signature.as_ref().ok_or(())?;

    let license_key_bytes = base64::decode(license_key).map_err(|_| ())?;
    let license_key_string = String::from_utf8(license_key_bytes.clone()).map_err(|_| ())?;

    let signature_bytes = base64::decode(signature).map_err(|_| ())?;

    let serde_lk: SerdeLicenseKey = serde_json::from_str(&license_key_string).map_err(|_| ())?;

    Ok(LicenseKey {
      ProductId: serde_lk.ProductId,
      Id: serde_lk.Id,
      Key: serde_lk.Key,
      Created: serde_lk.Created,
      Expires: serde_lk.Expires,
      Period: serde_lk.Period,
      F1: serde_lk.F1,
      F2: serde_lk.F2,
      F3: serde_lk.F3,
      F4: serde_lk.F4,
      F5: serde_lk.F5,
      F6: serde_lk.F6,
      F7: serde_lk.F7,
      F8: serde_lk.F8,
      Notes: serde_lk.Notes,
      Block: serde_lk.Block,
      GlobalId: serde_lk.GlobalId,
      Customer: serde_lk.Customer,
      ActivatedMachines: serde_lk.ActivatedMachines,
      TrialActivation: serde_lk.TrialActivation,
      MaxNoOfMachines: serde_lk.MaxNoOfMachines,
      AllowedMachines: serde_lk.AllowedMachines.split('\n').map(|x| x.to_string()).collect(),
      DataObjects: serde_lk.DataObjects,
      SignDate: serde_lk.SignDate,

      license_key_bytes: license_key_bytes,
      signature_bytes: signature_bytes,
    })
  }
}

#[allow(non_snake_case)]
pub fn KeyActivate(token: &str, args: KeyActivateArguments<'_, '_>) -> Result<LicenseKey, ()> {
  let product_id = args.ProductId.to_string();
  let fields_to_return = args.FieldsToReturn.to_string();
  let floating_time_interval = args.FloatingTimeInterval.to_string();
  let max_overdraft = args.MaxOverdraft.to_string();

  let params = [
      ("token", token),
      ("ProductId", &product_id),
      ("Key", args.Key),
      ("MachineCode", args.MachineCode),
      ("FieldsToReturn", &fields_to_return),
      ("FloatingTimeInterval", &floating_time_interval),
      ("MaxOverdraft", &max_overdraft),

      ("Sign", "true"),
      ("SignMethod", "1"),
      ("v", "1"),
  ];


  let client = reqwest::Client::new();
  let mut res = client.post("https://app.cryptolens.io/api/key/Activate")
      .form(&params)
      .send()
      .map_err(|_| ())?;

  let s = res.text().map_err(|_| ())?;

  LicenseKey::from_str(&s)
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct RSAKeyValue {
  Modulus: String,
  Exponent: String,
}

impl LicenseKey {
  pub fn has_valid_signature(&self, public_key: &str) -> Result<bool, ()> {
    let public_key: RSAKeyValue = serde_xml_rs::from_str(public_key).map_err(|_| ())?;

    let modulus_bytes = base64::decode(&public_key.Modulus).map_err(|_| ())?;
    let exponent_bytes = base64::decode(&public_key.Exponent).map_err(|_| ())?;

    let modulus  = openssl::bn::BigNum::from_slice(&modulus_bytes).map_err(|_| ())?;
    let exponent = openssl::bn::BigNum::from_slice(&exponent_bytes).map_err(|_| ())?;

    let keypair = openssl::rsa::Rsa::from_public_components(modulus, exponent).map_err(|_| ())?;
    let keypair = openssl::pkey::PKey::from_rsa(keypair).map_err(|_| ())?;

    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &keypair).map_err(|_| ())?;

    verifier.update(&self.license_key_bytes).map_err(|_| ())?;
    verifier.verify(&self.signature_bytes).map_err(|_| ())
  }
}
