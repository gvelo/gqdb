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

use anyhow::Error;
use crate::{time, Id};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Qso {
    id: Id,
    station_id: Id,
    callsign: String,
    datetime: u64,
    freq: u64,
    mode: String,
    rst: String,
    comments: String,
    created_at: u64,
    version: u8,
    sig: Signature,
}

impl Qso {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keys: &Keypair,
        station_id: Id,
        callsign: String,
        datetime: u64,
        freq: u64,
        mode: String,
        rst: String,
        comments: String,
    ) -> Qso {
        let created_at = time::unix_timstamp();
        let version: u8 = 0;

        let id = Self::generate_id(
            &station_id,
            &callsign,
            datetime,
            freq,
            &mode,
            &rst,
            &comments,
            created_at,
            version,
        );

        let sig = id.sign(keys);

        Self {
            id,
            station_id,
            callsign,
            datetime,
            freq,
            mode,
            rst,
            comments,
            created_at,
            version,
            sig,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_id(
        station_id: &Id,
        callsign: &str,
        datetime: u64,
        freq: u64,
        mode: &str,
        rst: &str,
        comments: &str,
        created_at: u64,
        version: u8,
    ) -> Id {
        let json: Value =
            json!([station_id, callsign, datetime, freq, mode, rst, comments, created_at, version]);
        let json_str = json.to_string();
        Id::new(&json_str)
    }

    pub fn verify(&self, station_pub_key: &XOnlyPublicKey) -> Result<(), Error> {
        let id = Self::generate_id(
            &self.station_id,
            &self.callsign,
            self.datetime,
            self.freq,
            &self.mode,
            &self.rst,
            &self.comments,
            self.created_at,
            self.version,
        );

        id.verify(station_pub_key, &self.sig)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::keys::generate_keypair;
    use crate::qso::Qso;
    use crate::Station;
    use codes_iso_3166::part_1::CountryCode;

    #[test]
    fn test_sign_verify() {
        let keys = generate_keypair();

        let station = Station::new(
            &keys,
            "LU4EV".to_string(),
            "Radio Club Caseros".to_string(),
            CountryCode::AR,
        );

        let qso = Qso::new(
            &keys,
            station.id.clone(),
            "LW3DZR".to_string(),
            1704141426,
            14250300,
            "CW".to_string(),
            "599".to_string(),
            "73".to_string(),
        );

        let qso_str = serde_json::to_string(&qso).unwrap();
        println!("{}", qso_str);

        qso.verify(&station.pub_key).unwrap();
    }
}
