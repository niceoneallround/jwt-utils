/*jslint node: true, vars: true */
const assert = require('assert');
const JWTUtils = require('../lib/jwtUtils').jwtUtils;
const JWTClaims = require('../lib/jwtUtils').claims;
const should = require('should');
const fs = require('fs');

function readfile(path) {
  'use strict';
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKeyPEM = readfile('rsa-public.pem');
const rsaX509certPEM = readfile('rsa.x509crt');

describe('1 Sign Syndicate Request Tests', function () {
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

  let subject = {
    '@id': 'http://bogus.domain.com/bogus1',
    '@type': 'http:/bogus.domain.com/type#Bogus',
    'http://bogus.domain.com/prop#name': 'heya', };

  let subjectJWT = JWTUtils.signSubject(subject, rs256Options, { subject: subject['@id'] });

  let syndRequest = {
    '@id': 'http://fake.synd.request',
    '@type': 'bogus',
  };

  let privacyPipeId = 'pipe1';

  it('1.1 HS256 - should create a JWT containing a syndicate request, a subjects_jwt, and a privacy pipe claim in the payload', function () {
    let props = { subject: syndRequest['@id'] };

    let token = JWTUtils.signSyndicateRequest(syndRequest, [subjectJWT], privacyPipeId, hs256Options, props);
    assert(token, 'no token produced');
    let verified = JWTUtils.newVerify(token, hs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', syndRequest['@id']);
    verified.should.have.property(JWTClaims.SYNDICATE_REQUEST_CLAIM, syndRequest);
    verified.should.have.property(JWTClaims.SUBJECT_JWTS_CLAIM);
    verified.should.have.property(JWTClaims.PRIVACY_PIPE_CLAIM, privacyPipeId);

    verified[JWTClaims.SUBJECT_JWTS_CLAIM].length.should.be.equal(1);
    let subjectPayload = JWTUtils.newVerify(verified[JWTClaims.SUBJECT_JWTS_CLAIM][0], rs256Options);
    subjectPayload.should.have.property(JWTClaims.SUBJECT_CLAIM, subject);
  }); //it 1.1

  it('1.2 RS256 - should should create a JWT containing a subject claim in the payload', function () {

    let props = { subject: syndRequest['@id'] };
    let token = JWTUtils.signSyndicateRequest(syndRequest, [subjectJWT], privacyPipeId, rs256Options, props);
    assert(token, 'no token produced');
    let verified = JWTUtils.newVerify(token, rs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', syndRequest['@id']);
    verified.should.have.property(JWTClaims.SYNDICATE_REQUEST_CLAIM, syndRequest);
    verified.should.have.property(JWTClaims.SUBJECT_JWTS_CLAIM);
    verified.should.have.property(JWTClaims.PRIVACY_PIPE_CLAIM, privacyPipeId);

    verified[JWTClaims.SUBJECT_JWTS_CLAIM].length.should.be.equal(1);
    let subjectPayload = JWTUtils.newVerify(verified[JWTClaims.SUBJECT_JWTS_CLAIM][0], rs256Options);
    subjectPayload.should.have.property(JWTClaims.SUBJECT_CLAIM, subject);

  }); //it 1.2

}); // decscribe 1
