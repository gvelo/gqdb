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

use secp256k1::Keypair;

pub fn generate_keypair() -> Keypair {
    let (secret_key, _) = secp256k1::generate_keypair(&mut rand::thread_rng());
    Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key)
}
