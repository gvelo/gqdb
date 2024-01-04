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

use crate::{time, Id};
use anyhow::Error;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub struct QsoData {
    station_id: Id,
    callsign: String,
    datetime: u64,
    freq: u64,
    mode: String,
    rst: String,
    comments: String,
}

struct QsoIdSrc<'a> {
    station_id: &'a Id,
    callsign: &'a str,
    datetime: u64,
    freq: u64,
    mode: &'a str,
    rst: &'a str,
    comments: &'a str,
    created_at: u64,
    version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Qso {
    pub id: Id,
    pub station_id: Id,
    pub callsign: String,
    pub datetime: u64,
    pub freq: u64,
    pub mode: String,
    pub rst: String,
    pub comments: String,
    pub created_at: u64,
    pub version: u8,
    pub sig: Signature,
}

impl Qso {
    pub fn new(qso_data: QsoData, keys: &Keypair) -> Qso {
        let created_at = time::unix_timstamp();
        let version: u8 = 0;

        let id = Self::generate_id(QsoIdSrc {
            station_id: &qso_data.station_id,
            callsign: &qso_data.callsign,
            datetime: qso_data.datetime,
            freq: qso_data.freq,
            mode: &qso_data.mode,
            rst: &qso_data.rst,
            comments: &qso_data.comments,
            created_at,
            version,
        });

        let sig = id.sign(keys);

        Self {
            id,
            station_id: qso_data.station_id,
            callsign: qso_data.callsign,
            datetime: qso_data.datetime,
            freq: qso_data.freq,
            mode: qso_data.mode,
            rst: qso_data.rst,
            comments: qso_data.comments,
            created_at,
            version,
            sig,
        }
    }

    fn generate_id(qso_id_src: QsoIdSrc) -> Id {
        let json: Value = json!([
            qso_id_src.station_id,
            qso_id_src.callsign,
            qso_id_src.datetime,
            qso_id_src.freq,
            qso_id_src.mode,
            qso_id_src.rst,
            qso_id_src.comments,
            qso_id_src.created_at,
            qso_id_src.version,
        ]);
        let json_str = json.to_string();
        Id::new(&json_str)
    }

    pub fn verify(&self, station_pub_key: &XOnlyPublicKey) -> Result<(), Error> {
        let id = Self::generate_id(QsoIdSrc {
            station_id: &self.station_id,
            callsign: &self.callsign,
            datetime: self.datetime,
            freq: self.freq,
            mode: &self.mode,
            rst: &self.rst,
            comments: &self.comments,
            created_at: self.created_at,
            version: self.version,
        });

        id.verify(station_pub_key, &self.sig)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::keys::generate_keypair;
    use crate::qso::{Qso, QsoData};
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
            QsoData {
                station_id: station.id.clone(),
                callsign: "LW3DZR".to_string(),
                freq: 1704141426,
                datetime: 14250300,
                mode: "CW".to_string(),
                rst: "599".to_string(),
                comments: "73".to_string(),
            },
            &keys,
        );

        let qso_str = serde_json::to_string(&qso).unwrap();
        println!("{}", qso_str);

        qso.verify(&station.pub_key).unwrap();
    }
}
