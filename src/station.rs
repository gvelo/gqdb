// Copyright 2021 The GQDB Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Error;
use codes_iso_3166::part_1::CountryCode;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;

use crate::id::Id;
use crate::time;

/// Station represent a radio station with a callsign and an operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Station {
    pub id: Id,
    pub pub_key: XOnlyPublicKey,
    pub callsign: String,
    pub operator: String,
    pub country: CountryCode,
    pub created_at: u64,
    pub version: u8,
    pub sig: Signature,
}

impl Station {
    /// Creates a new Station and signs the object.
    pub fn new(keys: &Keypair, callsign: String, operator: String, country: CountryCode) -> Self {
        let (pub_key, _) = keys.x_only_public_key();
        let created_at = time::unix_timstamp();

        let version: u8 = 0;
        let id = Self::generate_id(&pub_key, &callsign, &operator, country, created_at, version);
        let sig = id.sign(keys);
        Self {
            id,
            pub_key,
            callsign,
            operator,
            country,
            created_at,
            version,
            sig,
        }
    }

    /// Verify the object signature.
    pub fn verify(&self) -> Result<(), Error> {
        let id = Self::generate_id(
            &self.pub_key,
            &self.callsign,
            &self.operator,
            self.country,
            self.created_at,
            self.version,
        );
        id.verify(&self.pub_key, &self.sig)?;
        Ok(())
    }

    /// Generates the id for the station.
    fn generate_id(
        pub_key: &XOnlyPublicKey,
        callsign: &str,
        operator: &str,
        country: CountryCode,
        created_at: u64,
        version: u8,
    ) -> Id {
        let json: Value = json!([pub_key, callsign, operator, country, created_at, version]);
        let json_str = json.to_string();
        Id::new(&json_str)
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::generate_keypair;

    use super::*;

    #[test]
    fn test_sign_verify() {
        let (secret_key, _) = generate_keypair(&mut rand::thread_rng());
        let keys = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);

        let station = Station::new(
            &keys,
            "LU4EV".to_string(),
            "Radio Club Caseros".to_string(),
            CountryCode::AR,
        );

        assert!(station.verify().is_ok())
    }

    #[test]
    fn test_tampered_message() {
        let (secret_key, _) = generate_keypair(&mut rand::thread_rng());
        let keys = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);

        let mut station = Station::new(
            &keys,
            "LU4EV".to_string(),
            "Radio Club Caseros".to_string(),
            CountryCode::AR,
        );

        station.callsign = "tampered callsign".to_string();

        assert!(station.verify().is_err());
    }

    #[test]
    fn test_serde() {
        let json_str = r#"
        {
          "id": "dcc45a63ce8f2cf692cca8df74f9ab1f7adb978a1634c0d01671b209cf580f94",
          "pub_key": "a83757d9f8f381fe88db128e0572c14277181efeccbf013a0411bd37ba23930b",
          "callsign": "LU4EV",
          "operator": "Radio Club Caseros",
          "country": "AR",
          "created_at": 1702871644,
          "version": 0,
          "sig": "7568c4f83b41f8002231a17cfd697c5550270f2b1688ce1b5f5fda3f7f8f913cdd3a31cccdf4399a4a0e11ff198345d62ff17bb4bce4ce57722d80fd01dbd8e5"
        }
        "#;

        let station: Station = serde_json::from_str(json_str).unwrap();

        assert!(station.verify().is_ok());
    }
}
