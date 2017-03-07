/*jslint node: true */
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

describe('1 Sign Subject Query Result Tests', function () {
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

  let subjectQueryResult = {
    '@id': 'http://bogus.domain.com/bogus1',
    '@type': 'http:/bogus.domain.com/type#Bogus',
    'http://bogus.domain.com/prop#name': 'heya', };

  let subjects = ['a', 'b'];
  let privacyPipeId = 'pipe1';

  it('1.1 HS256 - should create a JWT containing a subject query and a privacy pipe claim in the payload', function () {
    let props = { subject: subjectQueryResult['@id'] };

    let token = JWTUtils.signSubjectQueryResult(subjectQueryResult, subjects, privacyPipeId, hs256Options, props);
    assert(token, 'no token produced');
    let verified = JWTUtils.newVerify(token, hs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', subjectQueryResult['@id']);
    verified.should.have.property(JWTClaims.PN_JWT_TYPE_CLAIM, JWTType.subjectQueryResult);
    verified.should.have.property(JWTClaims.SUBJECT_QUERY_RESULT_CLAIM, subjectQueryResult);
    verified.should.have.property(JWTClaims.SUBJECT_CLAIM, subjects);
    verified.should.have.property(JWTClaims.PRIVACY_PIPE_CLAIM, privacyPipeId);
  }); //it 1.1

  it('1.2 RS256 - should should create a JWT containing a subject query claim and pipe claim in the payload', function () {

    let props = { subject: subjectQueryResult['@id'] };
    let token = JWTUtils.signSubjectQueryResult(subjectQueryResult, subjects, privacyPipeId, rs256Options, props);
    assert(token, 'no token produced');
    let verified = JWTUtils.newVerify(token, rs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', subjectQueryResult['@id']);
    verified.should.have.property(JWTClaims.PN_JWT_TYPE_CLAIM, JWTType.subjectQueryResult);
    verified.should.have.property(JWTClaims.SUBJECT_QUERY_RESULT_CLAIM, subjectQueryResult);
    verified.should.have.property(JWTClaims.SUBJECT_CLAIM, subjects);
    verified.should.have.property(JWTClaims.PRIVACY_PIPE_CLAIM, privacyPipeId);
  }); //it 1.2

}); // decscribe 1
