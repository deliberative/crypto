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

const isBase64 = (str: string) => {
  const base64regex =
    /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;

  return base64regex.test(str);
};

const encodeToBase64 = (item: Uint8Array) => {
  return Buffer.from(item).toString("base64url");
};

const decodeFromBase64 = (item: string) => {
  const itemBuffer = Buffer.from(item, "base64url");

  return new Uint8Array(itemBuffer);
};

export default { isBase64, encodeToBase64, decodeFromBase64 };
