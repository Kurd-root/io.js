'use strict';

const {
  ObjectSetPrototypeOf,
  Symbol,
} = primordials;

const {
  EVP_PKEY_CMAC,
  EVP_PKEY_HMAC,
  EVP_PKEY_POLY1305,
  EVP_PKEY_SIPHASH,
  Hash: _Hash,
  Hmac: _Hmac,
  Mac: _Mac
} = internalBinding('crypto');

const {
  getDefaultEncoding,
  kHandle,
  toBuf
} = require('internal/crypto/util');

const {
  prepareSecretKey
} = require('internal/crypto/keys');

const { Buffer } = require('buffer');

const {
  ERR_CRYPTO_HASH_FINALIZED,
  ERR_CRYPTO_HASH_UPDATE_FAILED,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_OPT_VALUE
} = require('internal/errors').codes;
const { validateEncoding, validateString, validateUint32 } =
  require('internal/validators');
const { isArrayBufferView } = require('internal/util/types');
const LazyTransform = require('internal/streams/lazy_transform');
const kState = Symbol('kState');
const kFinalized = Symbol('kFinalized');

function Hash(algorithm, options) {
  if (!(this instanceof Hash))
    return new Hash(algorithm, options);
  if (!(algorithm instanceof _Hash))
    validateString(algorithm, 'algorithm');
  const xofLen = typeof options === 'object' && options !== null ?
    options.outputLength : undefined;
  if (xofLen !== undefined)
    validateUint32(xofLen, 'options.outputLength');
  this[kHandle] = new _Hash(algorithm, xofLen);
  this[kState] = {
    [kFinalized]: false
  };
  LazyTransform.call(this, options);
}

ObjectSetPrototypeOf(Hash.prototype, LazyTransform.prototype);
ObjectSetPrototypeOf(Hash, LazyTransform);

Hash.prototype.copy = function copy(options) {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  return new Hash(this[kHandle], options);
};

Hash.prototype._transform = function _transform(chunk, encoding, callback) {
  this[kHandle].update(chunk, encoding);
  callback();
};

Hash.prototype._flush = function _flush(callback) {
  this.push(this[kHandle].digest());
  callback();
};

Hash.prototype.update = function update(data, encoding) {
  encoding = encoding || getDefaultEncoding();

  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  if (typeof data === 'string') {
    validateEncoding(data, encoding);
  } else if (!isArrayBufferView(data)) {
    throw new ERR_INVALID_ARG_TYPE(
      'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
  }

  if (!this[kHandle].update(data, encoding))
    throw new ERR_CRYPTO_HASH_UPDATE_FAILED();
  return this;
};


Hash.prototype.digest = function digest(outputEncoding) {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();
  outputEncoding = outputEncoding || getDefaultEncoding();

  // Explicit conversion for backward compatibility.
  const ret = this[kHandle].digest(`${outputEncoding}`);
  state[kFinalized] = true;
  return ret;
};


function Hmac(hmac, key, options) {
  if (!(this instanceof Hmac))
    return new Hmac(hmac, key, options);
  validateString(hmac, 'hmac');
  key = prepareSecretKey(key);
  this[kHandle] = new _Hmac();
  this[kHandle].init(hmac, toBuf(key));
  this[kState] = {
    [kFinalized]: false
  };
  LazyTransform.call(this, options);
}

ObjectSetPrototypeOf(Hmac.prototype, LazyTransform.prototype);
ObjectSetPrototypeOf(Hmac, LazyTransform);

Hmac.prototype.update = Hash.prototype.update;

Hmac.prototype.digest = function digest(outputEncoding) {
  const state = this[kState];
  outputEncoding = outputEncoding || getDefaultEncoding();

  if (state[kFinalized]) {
    const buf = Buffer.from('');
    return outputEncoding === 'buffer' ? buf : buf.toString(outputEncoding);
  }

  // Explicit conversion for backward compatibility.
  const ret = this[kHandle].digest(`${outputEncoding}`);
  state[kFinalized] = true;
  return ret;
};

Hmac.prototype._flush = Hash.prototype._flush;
Hmac.prototype._transform = Hash.prototype._transform;

class Mac extends LazyTransform {
  constructor(mac, ...args) {
    validateString(mac, 'mac');

    let nid = EVP_PKEY_HMAC;
    let alg, key, options;

    switch (mac) {
      case 'cmac':
        nid = EVP_PKEY_CMAC;
        // Fall through.

      case 'hmac':
        [alg, key, options] = args;
        validateString(alg, 'alg');
        break;

      case 'poly1305':
        [key, options] = args;
        nid = EVP_PKEY_POLY1305;
        break;

      case 'siphash':
        [key, options] = args;
        nid = EVP_PKEY_SIPHASH;
        break;

      default:
        throw new ERR_INVALID_OPT_VALUE('mac', mac);
    }

    key = prepareSecretKey(key);
    super(options);

    this[kHandle] = new _Mac(nid, toBuf(key), alg);
  }

  _transform(chunk, encoding, callback) {
    this[kHandle].update(chunk, encoding);
    callback();
  }

  _flush(callback) {
    this.push(this[kHandle].digest());
    callback();
  }

  update(data, encoding) {
    encoding = encoding || getDefaultEncoding();

    if (typeof data === 'string') {
      validateEncoding(data, encoding);
    } else if (!isArrayBufferView(data)) {
      throw new ERR_INVALID_ARG_TYPE(
        'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
    }

    this[kHandle].update(data, encoding);
    return this;
  }

  final(outputEncoding) {
    return this[kHandle].final(outputEncoding || getDefaultEncoding());
  }
}

module.exports = {
  Hash,
  Hmac,
  Mac
};
