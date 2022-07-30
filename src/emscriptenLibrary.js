/*
 * Taken from https://github.com/jedisct1/libsodium.
 *
 * ISC License
 *
 * Copyright (c) 2013-2022
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

function randombytes_js() {
  try {
    var window_ = "object" === typeof window ? window : self;
    var crypto_ =
      typeof window_.crypto !== "undefined" ? window_.crypto : window_.msCrypto;
    var randomValuesStandard = function () {
      var buf = new Uint32Array(1);
      crypto_.getRandomValues(buf);
      return buf[0] >>> 0;
    };
    return randomValuesStandard();
  } catch (e) {
    try {
      var crypto = require("crypto");
      var randomValueNodeJS = function () {
        var buf = crypto["randomBytes"](4);
        return ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
      };
      return randomValueNodeJS();
    } catch (e) {
      throw "No secure random number generator found";
    }
  }
}

mergeInto(LibraryManager.library, {
  randombytes_js: () => {
    return randombytes_js();
  },
});
