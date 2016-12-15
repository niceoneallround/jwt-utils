/*jslint node: true, vars: true */
const assert = require('assert');
const jwtHelpers = require('../lib/jwtUtils').jwtUtils;
const jwtClaims = require('../lib/jwtUtils').claims;
const should = require('should');
const fs = require('fs');
const util = require('util');

function readfile(path) {
  'use strict';
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKeyPEM = readfile('rsa-public.pem');
const rsaX509certPEM = readfile('rsa.x509crt');

describe('jwtHelpers Tests', function () {
  'use strict';

  describe('1. JWT Tests using HS256', function () {

    var jwtOptions = {
      issuer: 'bob.com',
      type: 'HS256',
      secret: 'secret'
    };

    it('1.1 should create a JWT from JSON-LD graph and secret, and verify should work', function () {
      var request, token, verified;

      request = createTestObject();
      token = jwtHelpers.sign(jwtOptions, request);
      assert(token, 'no token produced');
      verified = jwtHelpers.verify(jwtOptions, token);
      verified.should.have.property('iss', 'bob.com');

      //console.log('verified result:%j', verified);
      checkTestObject(jwtHelpers.getPnGraph(verified));
    }); //it 1.1

    it('1.2 verifyGetPnGraph should verify a valid JWT and return the graph claim', function () {
      var request, token, body;

      request = createTestObject();
      token = jwtHelpers.sign(jwtOptions, request);
      body = jwtHelpers.verifyGetPnGraph(jwtOptions, token);
      checkTestObject(body);
    }); //it 1.2

    it('1.3 should create a JWT passing in a graph and a pipe, should record the graph and pipe in the claim', function () {
      var request, token, graph, props, verified, pp;

      props = {};
      props.privacyPipe = 'https://a_nice_privacy_pipe';
      request =  createTestGraph();

      token = jwtHelpers.signPipeData(jwtOptions, request, props);
      verified = jwtHelpers.verify(jwtOptions, token);
      graph = jwtHelpers.getPnGraph(verified);
      checkTestGraph(graph);

      pp = jwtHelpers.getPrivacyPipe(verified);
      assert(pp, util.format('no privacy pipe returned:%j?', verified));
    }); //it 1.3

    it('1.4 should create and verify and JWT with a passed in sub claim', function () {
      var graph, token, verified, props;

      graph = createTestGraph();
      props = {
        subject: 'http://dummy.subject'
      };

      token = jwtHelpers.sign(jwtOptions, graph, props);
      verified = jwtHelpers.verify(jwtOptions, token);
      verified.should.have.property('sub', 'http://dummy.subject');
    }); //it 1.4

    it('1.5 should support decode with not checking signature', function () {
      var graph, token, decoded;

      graph = createTestGraph();
      token = jwtHelpers.sign(jwtOptions, graph);

      // decode gettting header and payload
      decoded = jwtHelpers.decode(token, { complete: true });
      decoded.should.have.property('header');
      decoded.should.have.property('payload');

      console.log('decoded JWT:%j', decoded);
    }); //it 1.5

  }); // describe 1

  describe('2. JWT Sign Metadata Tests', function () {

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

    let md = {
      '@type': 'http://localhost/md#1',
      'http://bogus.com/prop#1': '23'
    };

    it('2.1 should create a JWT containing a metadata claim in the payload - signed with a HS256', function () {
      let props = { subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1' };

      let token = jwtHelpers.signMetadata(md, hs256Options, props);
      assert(token, 'no token produced');
      let verified = jwtHelpers.newVerify(token, hs256Options);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
      verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
    }); //it 2.1

    it('2.2 should create a JWT containing a metadata claim in the payload - signed with a RS256', function () {
      let props = {
          subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1', };

      let token = jwtHelpers.signMetadata(md, rs256Options, props);
      assert(token, 'no token produced');

      //let decoded = jwtHelpers.decode(token, { complete: true });
      /*console.log('*** decoded.header: %j', decoded.header);
      console.log('*** decoded.payload: %j', decoded.payload);
      console.log('*** decoded.signature: %j', decoded.signature);*/

      let verified = jwtHelpers.newVerify(token);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
      verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
    }); //it 2.2

    it('2.3 should create a JWT containing a metadata claim and provision in the payload - signed with a RS256', function () {
      let props = {
          subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1',
          provision: 'provision-data', };

      let token = jwtHelpers.signMetadata(md, rs256Options, props);
      assert(token, 'no token produced');

      //let decoded = jwtHelpers.decode(token, { complete: true });
      /*console.log('*** decoded.header: %j', decoded.header);
      console.log('*** decoded.payload: %j', decoded.payload);
      console.log('*** decoded.signature: %j', decoded.signature);*/

      let verified = jwtHelpers.newVerify(token);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.have.property(jwtClaims.PROVISION_CLAIM, 'provision-data');
      verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
      verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
    }); //it 2.3

  }); // decscribe 2

  describe('3. JWT Sign Data Tests', function () {

    let hs256Options, data, rs256Options;

    hs256Options = {
      issuer: 'bob.com',
      type: 'HS256',
      secret: 'secret'
    };

    rs256Options = {
      issuer: 'bob.com',
      type: 'RS256',
      privateKey: rsaPrivateKey,
      publicKeyPEM: rsaPublicKeyPEM,
      x509CertPEM: rsaX509certPEM,
    };

    data = {
      '@id': 'http://pn.id/fake_id',
      '@type': 'http://localhost/type#1',
      'http://bogus.com/prop#1': '23'
    };

    it('3.1 should create a JWT containing a graph claim in the payload - signed with a HS256', function () {
      let token, verified,
          props = { subject: data['@id'] };

      token = jwtHelpers.signData(data, hs256Options, props);
      assert(token, 'no token produced');
      verified = jwtHelpers.newVerify(token, hs256Options);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.PN_GRAPH_CLAIM);
      verified.should.not.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
    }); //it 3.1

    it('3.2 should create a JWT containing a graph claim in the payload - signed with a RS256', function () {
      var token, verified, decoded, temp,
        props = {
          subject: data['@id'], };

      token = jwtHelpers.signData(data, rs256Options, props);
      assert(token, 'no token produced');

      decoded = jwtHelpers.decode(token, { complete: true });

      /*console.log('*** decoded.header: %j', decoded.header);
      console.log('*** decoded.payload: %j', decoded.payload);
      console.log('*** decoded.signature: %j', decoded.signature);*/

      verified = jwtHelpers.newVerify(token);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.PN_GRAPH_CLAIM);
      temp =  jwtHelpers.getPnGraph(verified);
      temp.should.have.property('@id', props.subject);
      verified.should.not.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
    }); //it 3.2

    it('3.3 should create a JWT containing a graph claim in the payload and a pipe - signed with a HS256', function () {
      let token, verified,
          props = { subject: data['@id'], privacyPipe: 'a-pipe' };

      token = jwtHelpers.signData(data, hs256Options, props);
      assert(token, 'no token produced');
      verified = jwtHelpers.newVerify(token, hs256Options);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.PN_GRAPH_CLAIM);
      verified.should.not.have.property(jwtClaims.METADATA_CLAIM);
      verified.should.have.property(jwtClaims.PRIVACY_PIPE_CLAIM, 'a-pipe');
    }); //it 3.3

  }); // decscribe 3

  describe('4. JWT Sign Provision Tests', function () {

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

    let provision = {
      '@type': 'http://localhost/prov#1',
      'http://bogus.com/prop#1': '23'
    };

    it('4.1 should create a JWT containing a provision claim the payload - signed with a HS256', function () {
      let token, verified,
          props = { subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1',
                    privacyPipe: '1' };

      token = jwtHelpers.signProvision(provision, hs256Options, props);
      assert(token, 'no token produced');
      verified = jwtHelpers.newVerify(token, hs256Options);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.PROVISION_CLAIM, provision);
      verified.should.have.property(jwtClaims.PRIVACY_PIPE_CLAIM, props.privacyPipe);
      verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
    }); //it 4.1

    it('4.2 should create a JWT containing a metadata claim in the payload - signed with a RS256', function () {
      var token, verified, decoded,
        props = {
          subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1',
          privacyPipe: '1', };

      token = jwtHelpers.signProvision(provision, rs256Options, props);
      assert(token, 'no token produced');

      decoded = jwtHelpers.decode(token, { complete: true });

      /*console.log('*** decoded.header: %j', decoded.header);
      console.log('*** decoded.payload: %j', decoded.payload);
      console.log('*** decoded.signature: %j', decoded.signature);*/

      verified = jwtHelpers.newVerify(token);
      verified.should.have.property('iss', 'bob.com');
      verified.should.have.property('sub', props.subject);
      verified.should.have.property(jwtClaims.PROVISION_CLAIM, provision);
      verified.should.have.property(jwtClaims.PRIVACY_PIPE_CLAIM, props.privacyPipe);
      verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
    }); //it 4.2
  }); // decscribe 4

}); // describe

describe('5 JWT Encrypt Key Metadata Claim (EKMD) Tests', function () {
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

  let ekmd = {
    kty: 'a_kty',
    k: { '@type': 'a_type', '@value': 'a_value' },
  };

  it('5.1 should create a JWT containing a encrypt key metadata claim in the payload - signed with a HS256', function () {
    let props = { subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1' };

    let token = jwtHelpers.signEncryptKeyMetadata(ekmd, hs256Options, props);
    assert(token, 'no token produced');
    let verified = jwtHelpers.newVerify(token, hs256Options);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', props.subject);
    verified.should.have.property(jwtClaims.ENCRYPT_KEY_MD_CLAIM, ekmd);
    verified.should.not.have.property(jwtClaims.METADATA_CLAIM);
    verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
    verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
  }); //it 5.1

  it('5.2 should create a JWT containing an encrypt key metadata claim in the payload - signed with a RS256', function () {
    let props = {
        subject: 'http://md.pn.id.webshield.io/dummy/com/noway#1', };

    let token = jwtHelpers.signEncryptKeyMetadata(ekmd, rs256Options, props);
    assert(token, 'no token produced');

    //let decoded = jwtHelpers.decode(token, { complete: true });
    /*console.log('*** decoded.header: %j', decoded.header);
    console.log('*** decoded.payload: %j', decoded.payload);
    console.log('*** decoded.signature: %j', decoded.signature);*/

    let verified = jwtHelpers.newVerify(token);
    verified.should.have.property('iss', 'bob.com');
    verified.should.have.property('sub', props.subject);
    verified.should.have.property(jwtClaims.ENCRYPT_KEY_MD_CLAIM, ekmd);
    verified.should.not.have.property(jwtClaims.METADATA_CLAIM);
    verified.should.not.have.property(jwtClaims.PN_GRAPH_CLAIM);
    verified.should.not.have.property(jwtClaims.PRIVACY_PIPE_CLAIM);
  }); //it 5.2

}); // decscribe 5

//--------------------
// HELPER FUNCTIONS
//--------------------

function createTestObject() {
  'use strict';
  return { '@id': 'http://bogus.domain.com/bogus1',
        '@type': 'http:/bogus.domain.com/type#Bogus',
        'http:bogus.domain.com/prop#name': 'heya' };
}

function createTestGraph() {
  'use strict';
  return { '@graph': [createTestObject()] };
}

function checkTestGraph(graph) {
  'use strict';
  graph.should.have.property('@graph');
  return checkTestObject(graph['@graph'][0]);
}

function checkTestObject(obj) {
  'use strict';
  let canon = createTestObject();
  obj.should.have.property('@id', canon['@id']);
  obj.should.have.property('@type', canon['@type']);
  obj.should.have.property('http:bogus.domain.com/prop#name', canon['http:bogus.domain.com/prop#name']);
}
