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

import wordlist from "./wordlist.json";

import randomBytes from "../utils/randomBytes";

import sha512 from "../hash/sha512";

/**
 * Generates a sequence of words chosen from a prespecified wordlist
 * that represents a random seed that
 * can be translated later into a cryptographic keypair.
 * With a strength of 128 bits of entropy you get 12 words.
 * In every additional step you get 3 more words. The maximum is
 * set to 512 bits of entropy, or 48 words!
 *
 * @param strength - Entropy bits
 * @returns The mnemonic from the wordlist.
 *
 */
const generateMnemonic = async (
  strength:
    | 128
    | 160
    | 192
    | 224
    | 256
    | 288
    | 320
    | 352
    | 384
    | 416
    | 448
    | 480
    | 512 = 128,
): Promise<string> => {
  // if (strength % 32 !== 0) {
  //   throw new TypeError("Mnemonic strength needs to be multiple of 32.");
  // }

  // if (!wordlist) throw new Error("English wordlist could not be loaded.");

  // Between 16 and 64 and multiple of 4
  const entropy = await randomBytes(strength / 8);

  // if (entropy.length < 16) throw new TypeError("Entropy length too small.");

  // if (entropy.length > 64) throw new TypeError("Entropy length too large.");

  // if (entropy.length % 4 !== 0)
  //   throw new TypeError("Entropy length is not multiple of 4.");

  const entropyBits = entropy.reduce(
    (str, byte) => str + byte.toString(2).padStart(8, "0"),
    "",
  );

  const CS = strength / 32;
  const entropyHash = await sha512(entropy);
  const checksumBits = entropyHash
    .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
    .slice(0, CS);

  const bits = entropyBits + checksumBits;

  const chunks = bits.match(/(.{1,11})/g) as RegExpMatchArray;

  // if (!chunks)
  //   throw new Error("Did not find enough 1s and 11s in binary format.");

  const words = chunks.map((binary: string): string => {
    const index = parseInt(binary, 2);
    return wordlist[index];
  });

  return words.join(" ");
};

export default generateMnemonic;
