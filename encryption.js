const crypto = require('crypto');
const debug = require('debug')('cookie-session');


/**
 * Encrypt the given `plaintext` string, returning the ciphertext.
 * @param {Buffer} cryptKey - The encryption key. Should ideally be 32
 *   bytes long.
 * @param {Buffer} initVector - The initialization vector. Should be
 *   cryptographically randomized.
 * @param {string} plaintext - A UTF8-encoded string of what needs to be
 *   encrypted.
 * @returns {Buffer}
 * @private
 */
function _generateCiphertext(cryptKey, initVector, plaintext) {
  var cipher = crypto.createCipheriv('aes-256-cbc', cryptKey, initVector);

  return Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
}

/**
 * Decrypt the given `ciphertext` string, returning the plaintext encoded
 *   in UTF-8.
 * @param {Buffer} cryptKey - The encryption key. Needs to be the same as
 *   the one used in `_generateCiphertext()`.
 * @param {Buffer} initVector - The initialization vector. Needs to be the
 *   same as the one used in `_generateCiphertext()`.
 * @param {Buffer} ciphertext - A binary buffer of what needs to be
 *   decrypted.
 * @returns {string}
 * @private
 */
function _generatePlaintext(cryptKey, initVector, ciphertext) {
  var decipher = crypto.createDecipheriv('aes-256-cbc', cryptKey, initVector);
  return decipher.update(ciphertext) + decipher.final();
}

/**
 * Generate a hash of the given `ciphertext`. Provides authentication for
 *   the encrypted binary buffer.
 * @param {Buffer} hmacKey - The HMAC key. Should ideally be 64 bytes long.
 * @param {Buffer} ciphertext - A binary buffer of encrypted data.
 * @returns {string}
 * @private
 */
function _generateHmac(hmacKey, ciphertext) {
  return crypto.createHmac('sha256', hmacKey).update(ciphertext).digest();
}


/**
 * Encrypt the given `plaintext` string, returning a base64-encoded string.
 * An explanation of this string (the `blob`) can be found further below.
 * @param {Buffer} cryptKey - The encryption key. Should ideally be 32
 *   bytes long.
 * @param {Buffer} hmacKey - The HMAC key. Should be different from
 *   `cryptKey` and ideally be 64 bytes long.
 * @param {string} plaintext - A UTF8-encoded string of what needs to be
 *   encrypted.
 * @returns {string}
 * @throws When the initialization vector cannot be randomized properly.
 * @public
 */
exports.encrypt = function(cryptKey, hmacKey, plaintext) {
  /*
   * The `blob` is a base64-encoded concatenation of three strings of the
   * following.
   *
   * +-----+------+-------------------------+
   * | IV  | HMAC | Encrypted data...       |
   * +-----+------+-------------------------+
   *
   * IV will be 16 bytes long.
   * HMAC will be 32 bytes long.
   * The rest is encrypted data.
   */
  var initVector = crypto.randomBytes(16);
  var ciphertext = _generateCiphertext(cryptKey, initVector, plaintext);
  var hmac = _generateHmac(hmacKey, ciphertext);

  debug('plaintext size: ' + plaintext.length);
  debug('ciphertext size: ' + ciphertext.length);

  return Buffer.concat([
    initVector,
    hmac,
    ciphertext,
  ]).toString('base64');
};

/**
 * Decrypt the given `blob` string, returning the original plaintext
 * encoded in UTF-8. An explanation of this `blob` string can be found in
 * `encrypt()`.
 * @param {Buffer} cryptKey - The encryption key. Needs to be the same one
 *   used with `encrypt()`.
 * @param {Buffer} hmacKey - The HMAC key. Needs to be the same one used
 *   with `encrypt()`.
 * @param {string} blob - A base64-encoded string of three Buffer's that
 *   was returned from `encrypt()`.
 * @returns {string}
 * @throws When the HMAC check fails.
 * @public
 */
exports.decrypt = function(cryptKey, hmacKey, blob) {
  var INIT_VECTOR_SIZE = 16;
  var HMAC_SIZE = 32;

  var blobBuffer = new Buffer(blob, 'base64');
  var initVector = blobBuffer.slice(0, INIT_VECTOR_SIZE);
  var hmac = blobBuffer.slice(INIT_VECTOR_SIZE, INIT_VECTOR_SIZE + HMAC_SIZE);
  var ciphertext = blobBuffer.slice(INIT_VECTOR_SIZE + HMAC_SIZE);

  if (hmac.toString('base64') !==
      _generateHmac(hmacKey, ciphertext).toString('base64')) {
    throw new Error('HMAC check failed!');
  }

  return _generatePlaintext(cryptKey, initVector, ciphertext).toString('base64');
};

