/*jslint node: true, vars: true */
/*
  Test Subject JWT
*/
const assert = require('assert');
const jwtHelpers = require('../lib/jwtUtils').jwtUtils;
const jwtClaims = require('../lib/jwtUtils').claims;
const should = require('should');
const fs = require('fs');

function readfile(path) {
  'use strict';
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKeyPEM = readfile('rsa-public.pem');
const rsaX509certPEM = readfile('rsa.x509crt');

describe('1 Sign Subject Tests', function () {
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
    'http:bogus.domain.com/prop#name': 'heya', };

  let jwtProps = { subject: subject['@id'], privacyPipe: 'pipe-1-id', };

  let pnDataModelId = '23';
  let syndicationId = 'syndId-1';

  it('1.1 HS256 - hould create a JWT containing a subject claim in the payload', function () {

    let token = jwtHelpers.signSubject(subject, pnDataModelId, syndicationId, hs256Options, jwtProps);
    assert(token, 'no token produced');
    let verified = jwtHelpers.newVerify(token, hs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', subject['@id']);
    verified.should.have.property(jwtClaims.PN_DATA_MODEL_CLAIM, pnDataModelId);
    verified.should.have.property(jwtClaims.SUBJECT_CLAIM, subject);
    verified.should.have.property(jwtClaims.SYNDICATION_ID_CLAIM, syndicationId);
    verified.should.have.property(jwtClaims.JWT_ID_CLAIM);
    verified.should.have.property(jwtClaims.PRIVACY_PIPE_CLAIM, jwtProps.privacyPipe);
  }); //it 1.1

  it('1.2 RS256 - should should create a JWT containing a subject claim in the payload', function () {

    let token = jwtHelpers.signSubject(subject, pnDataModelId, syndicationId, rs256Options, jwtProps);
    assert(token, 'no token produced');

    let verified = jwtHelpers.newVerify(token);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', subject['@id']);
    verified.should.have.property(jwtClaims.PN_DATA_MODEL_CLAIM, pnDataModelId);
    verified.should.have.property(jwtClaims.SUBJECT_CLAIM, subject);
    verified.should.have.property(jwtClaims.SYNDICATION_ID_CLAIM, syndicationId);
    verified.should.have.property(jwtClaims.JWT_ID_CLAIM);
    verified.should.have.property(jwtClaims.PRIVACY_PIPE_CLAIM, jwtProps.privacyPipe);
  }); //it 1.2

  it('1.3 should set the JWT_ID_CLAIM to the passed in jwtID', function () {

    let props = { subject: subject['@id'], privacyPipe: 'p1', jwtID: '1', };
    let token = jwtHelpers.signSubject(subject, pnDataModelId, syndicationId, rs256Options, props);
    assert(token, 'no token produced');
    let verified = jwtHelpers.newVerify(token);
    verified.should.have.property(jwtClaims.JWT_ID_CLAIM, '1');
  }); //it 1.3

}); // decscribe 1
