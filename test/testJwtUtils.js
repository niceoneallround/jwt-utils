/*jslint node: true, vars: true */
var assert = require('assert'),
    jwtHelpers = require('../lib/jwtUtils').jwtUtils,
    should = require('should'),
    util = require('util');

describe('jwtHelpers Tests', function () {
  'use strict';

  function createTestObject() {
    return { '@id': 'http://bogus.domain.com/bogus1',
          '@type': 'http:/bogus.domain.com/type#Bogus',
          'http:bogus.domain.com/prop#name': 'heya' };
  }

  function createTestGraph() {
    return { '@graph': [createTestObject()] };
  }

  function checkTestGraph(graph) {
    graph.should.have.property('@graph');
    return checkTestObject(graph['@graph'][0]);
  }

  function checkTestObject(obj) {
    var canon = createTestObject();
    obj.should.have.property('@id', canon['@id']);
    obj.should.have.property('@type', canon['@type']);
    obj.should.have.property('http:bogus.domain.com/prop#name', canon['http:bogus.domain.com/prop#name']);
  }

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

}); // describe
