// Copyright 2023 The GQDB Authors
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

use crate::time::unix_timstamp;
use crate::Id;
use anyhow::{bail, Error};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Represents a certificate issued by a station..
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate {
    id: Id,
    issuer_id: Id,
    subject_id: Id,
    created_at: u64,
    version: u8,
    sig: Signature,
}

impl Certificate {
    pub fn new(issuer_id: Id, issuer_key_pair: &Keypair, subject_id: Id) -> Self {
        let created_at = unix_timstamp();
        let id = Self::generate_id(&issuer_id, &subject_id, created_at, 0);
        let sig = id.sign(issuer_key_pair);

        Self {
            id,
            issuer_id,
            subject_id,
            created_at,
            version: 0,
            sig,
        }
    }

    pub fn verify(&self, issuer_pub_key: &XOnlyPublicKey) -> Result<(), Error> {
        let id = Self::generate_id(
            &self.issuer_id,
            &self.subject_id,
            self.created_at,
            self.version,
        );

        if id != self.id {
            bail!("invalid id");
        }

        id.verify(issuer_pub_key, &self.sig)?;
        Ok(())
    }

    fn generate_id(issuer_id: &Id, subject_id: &Id, created_at: u64, version: u8) -> Id {
        let json: Value = json!([issuer_id, subject_id, created_at, version]);
        let json_str = json.to_string();
        Id::new(&json_str)
    }
}

#[cfg(test)]
mod tests {
    use crate::certificate::Certificate;
    use crate::keys::generate_keypair;
    use crate::Station;
    use codes_iso_3166::part_1::CountryCode;
    use serde_json;

    #[test]
    fn test_certificate() {
        let issuer_keys = generate_keypair();
        let subject_keys = generate_keypair();

        let issuer_station = Station::new(
            &issuer_keys,
            "LU4EV".to_string(),
            "Radio Club Caceros".to_string(),
            CountryCode::AR,
        )
        .unwrap();
        let subject_station = Station::new(
            &subject_keys,
            "LU2TST".to_string(),
            "Test Operator".to_string(),
            CountryCode::AR,
        )
        .unwrap();

        let certificate = Certificate::new(
            issuer_station.id.clone(),
            &issuer_keys,
            subject_station.id.clone(),
        );

        certificate.verify(&issuer_station.pub_key).unwrap();

        let json_msg = serde_json::to_string(&certificate).unwrap();

        println!("{}", json_msg);

        let cert_dese: Certificate = serde_json::from_str(&json_msg).unwrap();

        cert_dese.verify(&issuer_station.pub_key).unwrap();
    }

    #[test]
    fn test_tampered_message() {
        let issuer_keys = generate_keypair();
        let subject_keys = generate_keypair();

        let issuer_station = Station::new(
            &issuer_keys,
            "LU4EV".to_string(),
            "Radio Club Caceros".to_string(),
            CountryCode::AR,
        )
        .unwrap();
        let subject_station = Station::new(
            &subject_keys,
            "LU2TST".to_string(),
            "Test Operator".to_string(),
            CountryCode::AR,
        )
        .unwrap();

        let mut certificate = Certificate::new(
            issuer_station.id.clone(),
            &issuer_keys,
            subject_station.id.clone(),
        );

        certificate.verify(&issuer_station.pub_key).unwrap();

        certificate.version = 1;

        assert!(certificate.verify(&issuer_station.pub_key).is_err());
    }
}
