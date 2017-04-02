/*jslint node: true, vars: true */
/*
  Test SHA HASH A JWT
*/
const assert = require('assert');
const crypto = require('crypto');
const JWTUtils = require('../lib/jwtUtils').jwtUtils;
const should = require('should');
const fs = require('fs');

function readfile(path) {
  'use strict';
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKeyPEM = readfile('rsa-public.pem');
const rsaX509certPEM = readfile('rsa.x509crt');

describe('1 Test creating a cryptographic hash of a JWT', function () {
  'use strict';

  //------------------
  // Create a test JWT
  //------------------
  let rs256Options = {
    issuer: 'bob.com',
    type: 'RS256',
    privateKey: rsaPrivateKey,
    publicKeyPEM: rsaPublicKeyPEM,
    x509CertPEM: rsaX509certPEM,
  };

  let subject = {
    '@id': 'http://bogus.domain.com/bogus1',
    '@type': 'http:/bogus.domain.com/type#Bogus',
    'http:bogus.domain.com/prop#name': 'heya', };

  let jwtProps = { subject: subject['@id'], privacyPipe: 'pipe-1-id', };
  let pnDataModelId = '23';
  let syndicationId = 'syndId-1';
  let testJWT = JWTUtils.signSubject(subject, pnDataModelId, syndicationId, rs256Options, jwtProps);
  assert(testJWT, 'no token produced');

  it('1.1 should produce a SHA256 of the whole JWT covers header, payload, and signature.', function () {

    // ok create a hash of the JWT
    const hash = crypto.createHash('sha256');
    hash.update(testJWT);
    let canonHash = hash.digest('hex');
    let cHash = JWTUtils.SHAJWT(testJWT);
    cHash.should.be.equal(canonHash);
  }); //it 1.1

}); // decscribe 1
