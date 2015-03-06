"use strict";

var sjcl = require("./sjcl");

////////////////////////////////////////////////////////////////////////////////
//  ECDSA key generation and deserialization
////////////////////////////////////////////////////////////////////////////////

// Generate ECDSA signing and verification keys. The signing key is protected
// by the provided password.
function ECDSA_key_gen(password) {
  var curve = sjcl.ecc.curves['c256'];
  var pair_sec = sjcl.bn.random(curve.r);
  var pair_sec_bits = pair_sec.toBits();
  var pair_pub_bits = curve.G.mult(pair_sec).toBits();
  var output = {};

  output.pub = bitarray_to_base64(pair_pub_bits);
  var salt = random_bitarray(128);
  var sk_der = bitarray_slice(KDF(password, salt), 0, 128);
  var sk_cipher = setup_cipher(sk_der);
  var pair_sec_enc = enc_gcm(sk_cipher, pair_sec_bits);
  output.sec = bitarray_to_base64(bitarray_concat(salt, pair_sec_enc));

  return output;
}

// Loads a password-protected base64 encoded ECDSA signing key.
function ECDSA_load_sec_key(sec_key_base64, password) {
  var curve = sjcl.ecc.curves['c256'];
  var key_enc = base64_to_bitarray(sec_key_base64);
  var salt = bitarray_slice(key_enc, 0, 128);
  var key_enc_main = bitarray_slice(key_enc, 128);
  var sk_der = bitarray_slice(KDF(password, salt), 0, 128);
  var sk_cipher = setup_cipher(sk_der);
  var pair_sec_bits = dec_gcm(sk_cipher, key_enc_main);
  var pair_sec = sjcl.bn.fromBits(pair_sec_bits);
  return new sjcl.ecc['ecdsa'].secretKey(curve, pair_sec);
}

// Loads a based64 encoded ECDSA verification key.
function ECDSA_load_pub_key(pub_key_base64) {
  var pair_pub_pt = sjcl.ecc.curves['c256'].fromBits(
    base64_to_bitarray(pub_key_base64));
  return new sjcl.ecc['ecdsa'].publicKey(sjcl.ecc.curves['c256'], pair_pub_pt);
}

////////////////////////////////////////////////////////////////////////////////
//  Utility functions relevant to TLS
////////////////////////////////////////////////////////////////////////////////

var PROTOCOL_MESSAGE_TYPE = {
  CHALLENGE: 0,
  RESPONSE: 1,
  SUCCESS: 2,
  END: 3,
};

var PROTOCOL_STATE = {
  START: 0,
  CHALLENGE: 1,
  SESSION: 2,
  END: 3,
  ABORT: 4,
};

var SESSION_EVENT = {
  CONNECT: 0,
  START: 1,
  MESSAGE: 2,
  END: 3,
  ABORT: 4,
};

function send_message(stream, type, msg, suid) {
  try {
    stream.write(JSON.stringify({
      'type': type,
      'message': msg,
      'suid': suid
    }));
  } catch(ex) { /* Ignored */ }
}

function log_with_prefix(prefix, msg) {
  return function(msg) {
    console.log('[' + prefix + '] ' + msg)
  }
}

////////////////////////////////////////////////////////////////////////////////
//  Cryptographic primitives
////////////////////////////////////////////////////////////////////////////////

var KDF = function(password, salt) {
  return sjcl.misc.pbkdf2(password, salt, 100000);
  // Takes about a second on a commodity laptop.
};

var HMAC = function(key, data) {
  return (new sjcl.misc.hmac(key)).encrypt(data);
};

var SHA256 = function(bitarray) {
  return sjcl.hash.sha256.hash(bitarray);
};

var ECDSA_sign = function(secret_key, message_bitarray) {
  return secret_key.sign(SHA256(message_bitarray));
}

var ECDSA_verify = function(public_key, message_bitarray, signature_bitarray) {
  return public_key.verify(SHA256(message_bitarray), signature_bitarray);
}

var setup_cipher = function(secret_key) {
  // Takes a secret key (for AES-128) and initializes SJCL's internal
  // cipher data structure.
  if (bitarray_len(secret_key) != 128) {
    throw "setup_cipher: only accepts keys for AES-128";
  }
  return new sjcl.cipher.aes(secret_key);
};

var enc_gcm = function(cipher_with_sk, plaintext) {
  // Encrypts using the GCM mode.
  // Note that the first argument must be a cipher data structure
  // (initialized by setup_cipher).
  var iv = random_bitarray(128);
  var v = sjcl.mode.gcm.encrypt(cipher_with_sk, plaintext, iv);
  var ciphertext = sjcl.bitArray.concat(iv, v);
  return ciphertext;
};

var dec_gcm = function(cipher_with_sk, ciphertext) {
  // Decrypts using the GCM mode.
  // Note that the first argument must be a cipher data structure
  // (initialized by setup_cipher).
  var iv = sjcl.bitArray.bitSlice(ciphertext, 0, 128);
  var c = sjcl.bitArray.bitSlice(ciphertext, 128);
  return sjcl.mode.gcm.decrypt(cipher_with_sk, c, iv);
};




////////////////////////////////////////////////////////////////////////////////
//  Conversions between data representations
////////////////////////////////////////////////////////////////////////////////

// Note that "bitarray" is a special SJCL-internal data structure.
// It is /not/ just an array of 0/1 values.

var bitarray_slice = function(bitarray, a, b) {
  // Returns bits [a,...,b) (half-open interval)
  //   -- i.e., slice(01010001, 1, 4) = 101
  return sjcl.bitArray.bitSlice(bitarray, a, b);
};

var bitarray_to_string = function(bitarray) {
  return sjcl.codec.utf8String.fromBits(bitarray);
};

var string_to_bitarray = function(str) {
  return sjcl.codec.utf8String.toBits(str);
};

var bitarray_to_hex = function(bitarray) {
  return sjcl.codec.hex.fromBits(bitarray);
};

var hex_to_bitarray = function(hex_str) {
  return sjcl.codec.hex.toBits(hex_str);
};

var bitarray_to_base64 = function(bitarray) {
  return sjcl.codec.base64.fromBits(bitarray);
};

var base64_to_bitarray = function(base64_str) {
  // Throws an exception if the string is not valid base64.
  return sjcl.codec.base64.toBits(base64_str);
};

var byte_array_to_hex = function(a) {
  var s = "";
  for (var i = 0; i < a.length; i++) {
    if (a[i] < 0 || a[i] >= 256) {
      throw "byte_array_to_hex: value outside byte range";
    }
    s += ((a[i]|0) + 256).toString(16).substr(1);
  }
  return s;
};

var hex_to_byte_array = function(s) {
  var a = [];
  if (s.length % 2 != 0) {
    throw "hex_to_byte_array: odd length";
  }
  for (var i = 0; i < s.length; i += 2) {
    a.push(parseInt(s.substr(i,2),16)|0);
  }
  return a;
};

// Internal: you should not need this function.
var word_to_bytes_acc = function(word, bytes) { 
  // word is a nonnegative integer, at most 2^31-1
  if (word < 0) {
    throw "word_to_bytes_acc: can't convert negative integer";
  }
  for (var i = 0; i < 4; i++) {
    bytes.push(word & 0xff);
    word = word >>> 8;
  }
};

// Internal: you should not need this function.
var word_from_bytes_sub = function(bytes, i_start) {
  if (!Array.isArray(bytes)) {
    console.log(bytes);
    console.trace();
    throw "word_from_bytes_sub: received non-array";
  }
  if (bytes.length < 4) {
    throw "word_from_bytes_sub: array too short";
  }
  var word = 0;
  for (var i = i_start + 3; i >= i_start; i--) {
    word <<= 8;
    word |= bytes[i];
  }
  return word;
};




////////////////////////////////////////////////////////////////////////////////
//  Conversions including padding
////////////////////////////////////////////////////////////////////////////////

var string_to_padded_byte_array = function(s_utf8, padded_len) {
  if (typeof(s_utf8) !== "string") {
    throw "to_padded_byte_array: received non-string";
  }
  var s = unescape(encodeURIComponent(s_utf8));
  var l = s.length;
  if (l > padded_len) {
    throw "to_padded_byte_array: string too long";
  }
  var bytes = [];
  word_to_bytes_acc(l, bytes);
  for (var i = 0; i < padded_len; i++) {
    // Note: in general, this kind of code may be vulnerable to timing attacks
    // (not considered in our threat model).  For our use case, these attacks
    // do not seem relevant (nor is it clear how one could mitigate them, since
    // the user will eventually manipulate passwords in memory in the clear).
    if (i < l) {
      bytes.push(s.charCodeAt(i));
    } else {
      bytes.push(0);
    }
  }
  return bytes;
};

var string_to_padded_bitarray = function(s_utf8, padded_len) {
  return sjcl.codec.hex.toBits(
    byte_array_to_hex(string_to_padded_byte_array(s_utf8, padded_len)));
};

var string_from_padded_byte_array = function(a, padded_len) {
  if (a.length != padded_len + 4) {
    throw "string_from_padded_byte_array: wrong length";
  }
  var l = word_from_bytes_sub(a, 0);
  var s = "";
  for (var i = 4; i < Math.min(4 + l, a.length); i++) {
    s += String.fromCharCode(a[i]);
  }
  var s_utf8 = decodeURIComponent(escape(s));
  return s_utf8;
};

var string_from_padded_bitarray = function(a, padded_len) {
  return string_from_padded_byte_array(
    hex_to_byte_array(sjcl.codec.hex.fromBits(a)), padded_len)
};




////////////////////////////////////////////////////////////////////////////////
//  Other utility functions
////////////////////////////////////////////////////////////////////////////////

var random_bitarray = function(len) {
  if (len % 32 != 0) {
    throw "random_bit_array: len not divisible by 32";
  }
  return sjcl.random.randomWords(len / 32, 0);
};

var bitarray_equal = function(a1, a2) {
  return sjcl.bitArray.equal(a1, a2);
};

var bitarray_len = function(a) {
  return sjcl.bitArray.bitLength(a);
};

var bitarray_concat = function(a1, a2) {
  return sjcl.bitArray.concat(a1, a2);
};

var dict_num_keys = function(d) {
  var c = 0;
  for (var k in d) {
    if (d.hasOwnProperty(k)) {
      ++c;
    }
  }
  return c;
};

function reverse_lookup(d, v) {
  for (var k in d) {
    if (d.hasOwnProperty(k) && d[k] === v) {
      return k;
    }
  }
  return undefined;
}

module.exports.ECDSA_key_gen = ECDSA_key_gen,
module.exports.ECDSA_load_sec_key = ECDSA_load_sec_key,
module.exports.ECDSA_load_pub_key = ECDSA_load_pub_key,
module.exports.KDF = KDF,
module.exports.HMAC = HMAC,
module.exports.SHA256 = SHA256,
module.exports.ECDSA_sign = ECDSA_sign,
module.exports.ECDSA_verify = ECDSA_verify,
module.exports.setup_cipher = setup_cipher,
module.exports.enc_gcm = enc_gcm,
module.exports.dec_gcm = dec_gcm,
module.exports.bitarray_slice = bitarray_slice,
module.exports.bitarray_to_string = bitarray_to_string,
module.exports.string_to_bitarray = string_to_bitarray,
module.exports.bitarray_to_hex = bitarray_to_hex,
module.exports.hex_to_bitarray = hex_to_bitarray,
module.exports.bitarray_to_base64 = bitarray_to_base64,
module.exports.base64_to_bitarray = base64_to_bitarray,
module.exports.byte_array_to_hex = byte_array_to_hex,
module.exports.hex_to_byte_array = hex_to_byte_array,
module.exports.string_to_padded_byte_array = string_to_padded_byte_array,
module.exports.string_to_padded_bitarray = string_to_padded_bitarray,
module.exports.string_from_padded_byte_array = string_from_padded_byte_array,
module.exports.string_from_padded_bitarray = string_from_padded_bitarray,
module.exports.random_bitarray = random_bitarray,
module.exports.bitarray_equal = bitarray_equal,
module.exports.bitarray_len = bitarray_len,
module.exports.bitarray_concat = bitarray_concat,
module.exports.dict_num_keys = dict_num_keys,
module.exports.reverse_lookup = reverse_lookup,
module.exports.PROTOCOL_MESSAGE_TYPE = PROTOCOL_MESSAGE_TYPE,
module.exports.PROTOCOL_STATE = PROTOCOL_STATE,
module.exports.SESSION_EVENT = SESSION_EVENT,
module.exports.send_message = send_message,
module.exports.log_with_prefix = log_with_prefix;
