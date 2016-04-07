/*jslint node: true, vars: true */
var assert = require('assert'),
    jwtHelpers = require('../lib/jwtUtils').jwtUtils,
    should = require('should'),
    util = require('util');

describe('jwtHelpers Tests', function () {
  'use strict';

  var jwtOptions = {
    issuer: 'bob.com',
    type: 'HS256',
    secret: 'secret'
  };

  function createTestObject() {
    return { '@id': 'http://bogus.domain.com/bogus1',
          '@type': 'http:/bogus.domain.com/type#Bogus',
          'http:bogus.domain.com/prop#name': 'heya' };
  }

  function createTestGraph() {
    return { '@graph': createTestObject() };
  }

  function checkTestGraph(graph) {
    return checkTestObject(graph['@graph']);
  }

  function checkTestObject(graph) {
    var canon = createTestObject();
    graph.should.have.property('@id', canon['@id']);
    graph.should.have.property('@type', canon['@type']);
    graph.should.have.property('http:bogus.domain.com/prop#name', canon['http:bogus.domain.com/prop#name']);
  }

  describe('1. JWT Tests using HMAC and shared secret', function () {

    it('1.1 sign a request and decode with object', function () {

      var request, token, decoded;

      request = createTestObject();
      token = jwtHelpers.sign(jwtOptions, request);
      assert(token, 'no token produced');
      decoded = jwtHelpers.verify(jwtOptions, token);
      checkTestObject(jwtHelpers.getPnGraph(decoded));
    }); //it 1.1

    it('1.2 sign a request and decode with the verify and get graph with object', function () {

      var request, token, body;

      request = createTestObject();
      token = jwtHelpers.sign(jwtOptions, request);
      assert(token, 'no token produced');
      body = jwtHelpers.verifyGetPnGraph(jwtOptions, token);
      checkTestObject(body);
    }); //it 1.2

    it('1.3 sign a request with a privacy pipe and decode with the verify and get graph and get privacy pipe', function () {

      var request, token, body, props, decoded, pp;

      props = {};
      props.privacyPipe = 'https://a_nice_privacy_pipe';
      request = createTestObject();

      token = jwtHelpers.sign(jwtOptions, request, props);
      assert(token, 'no token produced');

      decoded = jwtHelpers.verify(jwtOptions, token);
      console.log('JWT tests - decoded:%j', decoded);

      body = jwtHelpers.getPnGraph(decoded);
      body.should.have.property('@id', request['@id']);

      pp = jwtHelpers.getPrivacyPipe(decoded);
      assert(pp, util.format('no privacy pipe returned:%j?', decoded));
    }); //it 1.3

    it('1.4 sign a request and decode with a graph', function () {
      var request, token, decoded;

      request = createTestGraph();
      token = jwtHelpers.signPipeData(jwtOptions, request);
      assert(token, 'no token produced');
      decoded = jwtHelpers.verify(jwtOptions, token);
      checkTestGraph(jwtHelpers.getPnGraph(decoded));
    }); //it 1.4

  }); // describe 1

}); // describe
