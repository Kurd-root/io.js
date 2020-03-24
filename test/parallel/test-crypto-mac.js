'use strict';

const common = require('../common');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');

assert.throws(() => crypto.createMac('boom', 'secret'),
              /Unknown message digest/);

// hmac
{
  const expected =
    Buffer.from('1b2c16b75bd2a870c114153ccda5bcfc' +
                'a63314bc722fa160d690de133ccbb9db', 'hex');
  const actual = crypto.createMac('sha256', 'secret').update('data').digest();
  assert.deepStrictEqual(actual, expected);
}

// poly1305
{
  const key =
    Buffer.from(
      '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
      'hex');
  const data =
    Buffer.from(
      '2754776173206272696c6c69672c20616e642074686520736c6974687920' +
      '746f7665730a446964206779726520616e642067696d626c6520696e2074' +
      '686520776162653a0a416c6c206d696d737920776572652074686520626f' +
      '726f676f7665732c0a416e6420746865206d6f6d65207261746873206f75' +
      '7467726162652e',
      'hex');
  const expected = Buffer.from('4541669a7eaaee61e708dc7cbcc5eb62', 'hex');
  const actual = crypto.createMac('poly1305', key).update(data).digest();
  assert.deepStrictEqual(actual, expected);
}

// siphash
{
  const key = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex');
  const data = Buffer.from('000102030405', 'hex');
  const expected = Buffer.from('14eeca338b208613485ea0308fd7a15e', 'hex');
  const actual = crypto.createMac('siphash', key).update(data).digest();
  assert.deepStrictEqual(actual, expected);
}
