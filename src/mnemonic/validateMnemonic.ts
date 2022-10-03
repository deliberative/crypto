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

import hash from "../hash";

const normalize = (str: string) => {
  return (str || "").normalize("NFKD");
};

const mnemonicToEntropy = async (mnemonic: string): Promise<boolean> => {
  if (!wordlist) throw new Error("Could not load english wordlist");

  const words = normalize(mnemonic).split(" ");
  if (words.length % 3 !== 0)
    throw new Error("Number of words in mnemonic must be multiple of three.");

  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word: string): string => {
      const index = wordlist.indexOf(word);
      if (index === -1) {
        throw new Error("Could not find word in wordlist.");
      }

      return index.toString(2).padStart(11, "0");
      // return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // convert bits to entropy
  const entropyBitsMatched = entropyBits.match(/(.{1,8})/g);

  if (!entropyBitsMatched) throw new Error("Invalid entropy bits.");

  // calculate the checksum and compare
  const entropy = entropyBitsMatched.map((bin: string) => parseInt(bin, 2));

  if (entropy.length < 16)
    throw new Error("Entropy length too small (less than 128 bits).");

  if (entropy.length > 32)
    throw new Error("Entropy length too large (more than 256 bits).");

  if (entropy.length % 4 !== 0)
    throw new Error("Entropy length must be a multiple of 4.");

  const CS = entropy.length / 4;
  const entropyHash = await hash.sha512(Uint8Array.from([...entropy]));
  const newChecksum = entropyHash
    .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
    .slice(0, CS);

  if (newChecksum !== checksumBits) throw new Error("Invalid checksum.");

  return true;
};

const validateMnemonic = async (mnemonic: string): Promise<boolean> => {
  try {
    return await mnemonicToEntropy(mnemonic);
  } catch (e) {
    return false;
  }
};

export default validateMnemonic;
