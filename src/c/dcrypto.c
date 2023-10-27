// Copyright (C) 2023 Deliberative Technologies P.C.
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

#include "../../libsodium/src/libsodium/sodium/codecs.c"
#include "../../libsodium/src/libsodium/sodium/core.c"
#include "../../libsodium/src/libsodium/sodium/utils.c"

#include "./chacha20poly1305/chacha20poly1305.c"
#include "./ed25519/ed25519.c"
#include "./hash/hash.c"
#include "./utils/utils.c"

// Merkle
#include "./merkle/get_merkle_proof.c"
#include "./merkle/get_merkle_root.c"
#include "./merkle/get_merkle_root_from_proof.c"
#include "./merkle/verify_merkle_proof.c"

// Shamir
#include "./shamir/polynomial.c"
#include "./shamir/restore_secret.c"
#include "./shamir/split_secret.c"
