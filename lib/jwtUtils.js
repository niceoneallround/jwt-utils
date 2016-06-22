/*jslint node: true, vars: true */

var assert = require('assert'),
    jwt = require('jsonwebtoken'),
    jwtUtils = {},
    util = require('util'),
    GRAPH_PROP = 'https://pn.schema.webshield.io/prop#pn_graph', // place here so self contained
    PRIVACY_PIPE = 'https://pn.schema.webshield.io/prop#privacy_pipe';

//
// *jwtOptions - set of params to control the jwt actions
// *graph: can be a jsonld graph, an array of objects, or an object
// @props: contains other properties that should be placed into the JWT payload
//   props.privacyPipe
//
jwtUtils.sign = function sign(jwtOptions, graph, props) {
  'use strict';
  assert(jwtOptions, 'jwtOptions param missing');
  assert(jwtOptions.issuer, util.format('jwtOptions.issuer is missing:%j', jwtOptions));
  assert(jwtOptions.type, util.format('jwtOptions.type props missing:%j', jwtOptions));
  assert((jwtOptions.type === 'HS256'), util.format('jwtOptions.type must be HS256 as only type supported:%j', jwtOptions));
  assert(jwtOptions.secret, util.format('jwtOptions.secret props missing:%j', jwtOptions));
  assert(graph, 'graph param missing');

  if (props) {
    assert(!props.algorithm, util.format('props.algorithm should not be set as overrided:%j', props));
  }

  var payload = {}, options = {};

  options.issuer = jwtOptions.issuer;

  if (jwtOptions.type === 'HS256') {
    options.algorithm = 'HS256';
  }

  if (props) {
    if (props.privacyPipe) {
      payload[PRIVACY_PIPE] = props.privacyPipe;
    }

    if (props.issuer) {
      options.issuer = props.issuer;
    }

    if (props.subject) {
      options.subject = props.subject;
    }
  }

  /* Remove this code as confusing just let parties put in what they want for now
  if (graph['@graph']) {
    // already a jsonld graph so do nothing
    payload[GRAPH_PROP] = graph;
  } else {
    // not a jsonld graph so make it into one
    if (Array.isArray(graph)) {
      payload[GRAPH_PROP] = { '@graph': graph };
    } else {
      payload[GRAPH_PROP] = { '@graph': [graph] };
    }
  }*/
  payload[GRAPH_PROP] = graph;

  return jwt.sign(payload, jwtOptions.secret, options);
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
  assert(jwToken, util.format('jwToken param to verify missing'));

  var options = {};

  // note not checking the issuer or the subject
  try {
    if (jwtOptions.type === 'HS256') {
      options.algorithm = 'HS256';
      return jwt.verify(jwToken, jwtOptions.secret, options);
    }
  } catch (err) {
    throw err;
  }
};

//
// return the jsonld graph from inside the JWT
//
jwtUtils.getPnGraph = function getpnGraph(payload) {
  'use strict';
  return payload[GRAPH_PROP];
};

//
// return the privacy pipe from inside the JWT
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
