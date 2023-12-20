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

use anyhow::{Context, Error};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

/// Object Id
///
/// 32-bytes lowercase hex-encoded sha256 of the the serialized object data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id {
    bytes: [u8; 32],
}

impl Id {
    /// Creates a new Id from a str.
    pub fn new(value: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value);
        let hash = hasher.finalize();
        Self { bytes: hash.into() }
    }

    /// Sign the id.
    pub fn sign(&self, keys: &Keypair) -> Signature {
        keys.sign_schnorr(Message::from_digest(self.bytes))
    }

    /// Verify the id signature.
    pub fn verify(&self, pub_key: &XOnlyPublicKey, sig: &Signature) -> Result<(), Error> {
        let message = Message::from_digest(self.bytes);
        SECP256K1
            .verify_schnorr(sig, &message, pub_key)
            .context("failed to verify signature")?;
        Ok(())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            hex::serialize(self.bytes, serializer)
        } else {
            serializer.serialize_bytes(self.bytes.as_ref())
        }
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = if deserializer.is_human_readable() {
            hex::deserialize(deserializer)?
        } else {
            Deserialize::deserialize(deserializer)?
        };

        Ok(Self { bytes })
    }
}
