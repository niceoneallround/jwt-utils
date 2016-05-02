/*jslint node: true, vars: true */
var jwtHelpers = require('../lib/jwtUtils').jwtUtils,
    should = require('should');

describe('jwtHelpers Tests', function () {
  'use strict';

  describe('1. JWT Tests using HMAC and shared secret', function () {

    it('1.1 sign a request and decode with object', function () {

      var obj1, token1, jwtOptions1, decoded1, split1,
          obj2, token2, jwtOptions2,
          madeupToken,
          madeupPayload;

      obj1 = { '@id': 'http://bogus.domain.com/object', '@value': '23' };
      jwtOptions1 = { issuer: 'source.com', type: 'HS256', secret: 'source_private_secret' };

      obj2 = { '@id': 'http://bogus.domain.com/object', '@value': 'obfuscated' };
      jwtOptions2 = { issuer: 'pnode.com', type: 'HS256', secret: 'pnode_private_secret' };

      token1 = jwtHelpers.sign(jwtOptions1, JSON.stringify(obj1));
      console.log('------Original JWT from source token1:%s', token1);

      split1 = token1.split('.');
      console.log('------split1:%j', split1);
      console.log('------decode header:%s', new Buffer(split1[0], 'base64').toString('ascii'));

      token2 = jwtHelpers.sign(jwtOptions2, obj2);
      console.log('------Updated JWT from pnode token2:%s', token2);

      decoded1 = jwtHelpers.verify(jwtOptions1, token1);
      console.log('------decoded1:%j', decoded1);

      madeupToken = split1[0] + '.' + split1[1] + '.' + split1[2];
      console.log('------decoded madeuptoken with split:%j', jwtHelpers.verify(jwtOptions1, madeupToken));

      // lets base64 encode the payload
      madeupPayload = {
        'https://pn.schema.webshield.io/prop#pn_graph': JSON.stringify(obj1),
        iat: decoded1.iat,
        iss: 'source.com'
      };
      console.log('-------made up payload:%j', madeupPayload);
      console.log('------original payload:%j', decoded1);

      var b64MadeUpPayload =   new Buffer(JSON.stringify(madeupPayload)).toString('base64');
      console.log('-------made up b64 payload:%j', b64MadeUpPayload);
      console.log('------original b64 payload:%j', split1[1]);
      console.log('-------made up utf8 payload:%j',
            new Buffer(JSON.stringify(madeupPayload)).toString('utf8'));

      madeupToken = split1[0] + '.' +
                    new Buffer(JSON.stringify(madeupPayload)).toString('base64') + '.' +
                    split1[2];
      console.log('-------made up token:%s', madeupToken);
      console.log('-------orginal token:%s', token1);

      //
      // FIXME does not yet work as cannot create the base64 encoding
      // console.log('------decoded madeuptoken rebase64 payload:%j', jwtHelpers.verify(jwtOptions1, madeupToken));

    }); //it 1.1

  }); // describe 1

}); // describe
