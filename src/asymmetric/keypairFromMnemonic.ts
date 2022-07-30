// Copyright (C) 2022 Deliberative Technologies P.C.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as bip39 from "bip39";
import * as nacl from "tweetnacl";

const keypairFromMnemonic = async (mnemonic: string) => {
  const isValid = bip39.validateMnemonic(mnemonic);
  if (!isValid) throw new Error("Invalid mnemonic.");

  const seed = await bip39.mnemonicToSeed(mnemonic);
  const privateKeySeed = new Uint8Array(seed.toJSON().data.slice(0, 32));
  const keypair = nacl.sign.keyPair.fromSeed(privateKeySeed);
  if (!keypair) throw new Error("Invalid seed from mnemonic.");

  return keypair;
};

export default keypairFromMnemonic;
