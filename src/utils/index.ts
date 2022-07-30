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

import randomNumberInRange from "./randomNumberInRange";
import arrayRandomShuffle from "./arrayRandomShuffle";
import arrayRandomSubset from "./arrayRandomSubset";
import arraysAreEqual from "./arraysAreEqual";
import isBrowser from "./isBrowser";
import base64 from "./base64";

export default {
  randomNumberInRange,
  arrayRandomShuffle,
  arrayRandomSubset,
  arraysAreEqual,
  isBrowser,
  isBase64: base64.isBase64,
  encodeToBase64: base64.encodeToBase64,
  decodeFromBase64: base64.decodeFromBase64,
};
