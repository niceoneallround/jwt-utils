/*jslint node: true, vars: true */
const assert = require('assert');
const JWTUtils = require('../lib/jwtUtils').jwtUtils;
const JWTClaims = require('../lib/jwtUtils').claims;
const JWTType = require('../lib/jwtUtils').jwtType;
const should = require('should');
const fs = require('fs');

function readfile(path) {
  'use strict';
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKeyPEM = readfile('rsa-public.pem');
const rsaX509certPEM = readfile('rsa.x509crt');

describe('1 Sign Message Ack Tests', function () {
  'use strict';

  let hs256Options = {
    issuer: 'bob.com',
    type: 'HS256',
    secret: 'secret'
  };

  let rs256Options = {
    issuer: 'bob.com',
    type: 'RS256',
    privateKey: rsaPrivateKey,
    publicKeyPEM: rsaPublicKeyPEM,
    x509CertPEM: rsaX509certPEM,
  };

  let id = '23';

  it('1.1 HS256 - should create a JWT containing message ack claim',
    function () {
      let token = JWTUtils.signMessageAck(id, hs256Options);
      assert(token, 'no token produced');
      let verified = JWTUtils.newVerify(token, hs256Options);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', id);
      verified.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, id);
      verified.should.have.property(JWTClaims.PN_JWT_TYPE_CLAIM, JWTType.messageAck);
    }); //it 1.1

  it('1.2 RS256 - should create a JWT containing message ack claim', function () {
    let token = JWTUtils.signMessageAck(id, rs256Options);
    assert(token, 'no token produced');
    let verified = JWTUtils.newVerify(token, rs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', id);
    verified.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, id);
    verified.should.have.property(JWTClaims.PN_JWT_TYPE_CLAIM, JWTType.messageAck);
  }); //it 1.2

}); // decscribe 1
