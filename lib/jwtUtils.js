/*jslint node: true, vars: true */

var assert = require('assert'),
    jwt = require('jsonwebtoken'),
    jwtUtils = {},
    GRAPH_PROP = 'https://pn.schema.webshield.io/prop#pn_graph', // place here so self contained
    PRIVACY_PIPE = 'https://pn.schema.webshield.io/prop#privacy_pipe';

//
// *crypto - set of params to control the jwt actions
// *payload - JSON ld graph tp be placed in the domain PN_P.body property
// @props - set of props to be placed at the JWT level
//   props.privacyPipe
//
jwtUtils.sign = function sign(crypto, graph, props) {
  'use strict';
  assert(crypto, 'crypto param missing');
  assert(crypto.issuer, 'crypto.issuer is missing');
  assert(crypto.jwt, 'crypto.jwt props missing');
  assert(crypto.jwt.type, 'crypto.jwt.type is missing');
  assert(crypto.jwt.secret, 'crypto.jwt.secret is missing');

  var options = {},
      payload = {};

  payload[GRAPH_PROP] = graph;

  if ((props) && (props.privacyPipe)) {
    payload[PRIVACY_PIPE] = props.privacyPipe;
  }

  options.issuer = crypto.issuer;
  if (crypto.jwt.type === 'HS256') {
    options.algorithm = 'HS256';
    return jwt.sign(payload, crypto.jwt.secret, options);
  }
};

jwtUtils.verify = function verify(crypto, token) {
  'use strict';
  assert(crypto, 'cryto param missing');
  assert(crypto.jwt, 'crypto.jwt props missing');
  assert(crypto.jwt.type, 'crypto.jwt.type is missing');
  assert(crypto.jwt.secret, 'crypto.jwt.secret is missing');

  var options = {}, payload;

  try {
    if (crypto.jwt.type === 'HS256') {
      options.algorithm = 'HS256';
      payload = jwt.verify(token, crypto.jwt.secret, options);

      // validate issue is who expected
      return payload;
    }
  } catch (err) {
    throw err;
  }
};

//
// return the jsonld graph from inside the JWT
jwtUtils.getPnGraph = function getpnGraph(payload) {
  'use strict';
  return payload[GRAPH_PROP];
};

//
// return the jsonld graph from inside the JWT
jwtUtils.getPrivacyPipe = function getPrivacyPipe(payload) {
  'use strict';
  return payload[PRIVACY_PIPE];
};

// convenience routine to verify and get the PnGraph - used if only need graph
jwtUtils.verifyGetPnGraph = function verifyGetPnGraph(crypto, token) {
  'use strict';
  return jwtUtils.getPnGraph(
                  (jwtUtils.verify(crypto, token)));
};

module.exports = {
  jwtUtils: jwtUtils
};
