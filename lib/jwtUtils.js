/*jslint node: true, vars: true */

var assert = require('assert'),
    jwt = require('jsonwebtoken'),
    jwtUtils = {},
    util = require('util'),
    GRAPH_PROP = 'https://pn.schema.webshield.io/prop#pn_graph', // place here so self contained
    PRIVACY_PIPE = 'https://pn.schema.webshield.io/prop#privacy_pipe';

//
// *jwtOptions - set of params to control the jwt actions
// *payload - JSON ld data to be placed in the domain PN_P.body property - does enforce is a graph
// @props - set of props to be placed at the JWT level
//   props.privacyPipe
//
jwtUtils.sign = function sign(jwtOptions, graph, props) {
  'use strict';
  assert(jwtOptions, 'jwtOptions param missing');
  assert(jwtOptions.issuer, util.format('jwtOptions.issuer is missing:%j', jwtOptions));
  assert(jwtOptions.type, util.format('jwtOptions.type props missing:%j', jwtOptions));
  assert(jwtOptions.secret, util.format('jwtOptions.secret props missing:%j', jwtOptions));
  assert(graph, 'graph param missing');

  var options = {},
      payload = {};

  payload[GRAPH_PROP] = graph;

  if ((props) && (props.privacyPipe)) {
    payload[PRIVACY_PIPE] = props.privacyPipe;
  }

  options.issuer = jwtOptions.issuer;
  if (jwtOptions.type === 'HS256') {
    options.algorithm = 'HS256';
    return jwt.sign(payload, jwtOptions.secret, options);
  }
};

//
// *jwtOptions - set of params to control the jwt actions
// *payload - JSON ld graph to be placed in the domain PN_P.body property
// @props - set of props to be placed at the JWT level
//   props.privacyPipe
//
jwtUtils.signPipeData = function signPipeData(jwtOptions, graph, props) {
  'use strict';

  // The graph must have a top level @graph property - it can be a named or non named graph
  assert(graph, 'graph param missing');
  assert(graph['@graph'], util.format('The passed in graph must have a top level @graph property:%j', graph));

  return jwtUtils.sign(jwtOptions, graph, props);
};

// verify and unpack a JWT
jwtUtils.verify = function verify(jwtOptions, jwToken) {
  'use strict';
  assert(jwtOptions, 'jwtOptions param missing');
  assert(jwtOptions.type, util.format('jwtOptions.type props missing:%j', jwtOptions));
  assert(jwtOptions.secret, util.format('jwtOptions.secret props missing:%j', jwtOptions));
  assert(jwToken, util.format('jwt missing'));

  var options = {}, payload;

  try {
    if (jwtOptions.type === 'HS256') {
      options.algorithm = 'HS256';
      payload = jwt.verify(jwToken, jwtOptions.secret, options);

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
jwtUtils.verifyGetPnGraph = function verifyGetPnGraph(jwtOptions, token) {
  'use strict';
  return jwtUtils.getPnGraph(
                  (jwtUtils.verify(jwtOptions, token)));
};

module.exports = {
  jwtUtils: jwtUtils
};
