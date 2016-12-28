/*jslint node: true, vars: true */

/*
 Defines a set of private clams that are used by the PN and provides a set
 convenience routines that provide the following functionality

 - signMetadata - create JWT with metadata claim
 - signData - create a JWT with a pn graph claim
 - signPipeData - create a JWT with both a graph claim and a privacy pipe claim
 - newVerify - verify JWT either with HS256 or RS256 depending on need
 - decode - return decoded no verify
*/

const assert = require('assert');
const jwt = require('jsonwebtoken');
const util = require('util');

//-----------------
// Private claims that can be placed in the JWT payload
//-----------------

// holds the encrypt key metadata that is used by the privacy action instance
const ENCRYPT_KEY_MD_CLAIM = 'https://pn.schema.webshield.io/prop#encrypt_key_md';

// holds PN metadata, note the metadata JSONLD node is created from the
// JWT payload props such as sub, issuer, iat and the contents of the metadata
// claim. The contents are JSONLD compliant.
const METADATA_CLAIM = 'https://pn.schema.webshield.io/prop#metadata';

// holds an identity syndicate request jsonld node.
const SYNDICATE_REQUEST_CLAIM = 'https://pn.schema.webshield.io/prop#syndicate_request';

// holds an array of JWTs that each contain a subject claim. This is part of a JWT that
// contains a syndicate request claim
const SUBJECT_JWTS_CLAIM = 'https://pn.schema.webshield.io/prop#subject_jwts';

// holds a jsonld node that has a subject type, the sub of the jwt is the @id of
// the subject
const SUBJECT_CLAIM = 'https://pn.schema.webshield.io/prop#subject';

// holds a JSONLD compliant subject data
const PN_GRAPH_CLAIM = 'https://pn.schema.webshield.io/prop#pn_graph';

// holds the privacy pipe id
const PRIVACY_PIPE_CLAIM = 'https://pn.schema.webshield.io/prop#privacy_pipe';

// holds metadata that needs to be provisioned into the client, used as part
// of privacy pipe creation.
const PROVISION_CLAIM = 'https://pn.schema.webshield.io/prop#provision';

//--------------------
// Header private properties
//----------------------

// used to hold the PEM contents as could not use existing header params
const HEADER_PUBLIC_KEY_PEM = 'http://pn.schema.webshield.io/prop#jwk_pem';
const HEADER_X509_CERT_PEM = 'http://pn.schema.webshield.io/prop#x5c_pem';

var jwtUtils = {};

//
// Create a JWT wrapping data being send down a privacy pipe.
//
// The payload has the following private claims
// PN_GRAPH_CLAIM holds the data being sent
// PRIVACY_PIPE_CLAIM holds the pipe @id
//
// *jwtOptions - set of params to control the jwt actions
// *graph - JSON ld graph to send
// @props
//   props.privacyPipe
//
jwtUtils.signPipeData = function signPipeData(jwtOptions, graph, props) {
  'use strict';

  // The graph must have a top level @graph property - it can be a named or non named graph
  assert(graph, 'signPipeData graph param missing');
  assert(graph['@graph'], util.format('The passed in graph must have a top level @graph property:%j', graph));
  assert(props, 'signPipeData - props param missing');
  assert(props.privacyPipe, util.format('signPipeData - props.privacyPipe missing:%j', props));

  return jwtUtils.sign(jwtOptions, graph, props);
};

//
// Create a JWT that contains an encrypt key metadata claim.
// *ekmd - this is placed in the ENCRYPT_KEY_MD_CLAIM
// *jwtOptions - control the signing
// *props
//   subject: the encrypt key md @id
//   issuer: comes from the jwtOptions
//
jwtUtils.signEncryptKeyMetadata = function signEncryptKeyMetadata(ekmd, jwtOptions, props) {
  'use strict';
  assert(ekmd, 'signEncryptKeyMetadata ekmd param missing');
  assert(props, 'signEncryptKeyMetadata props param missing');

  // The encrypt key metadata JWT payload must have a JWT sub claim so check passed in.
  // Note the issuer is checked in lower levels as required.
  assert(props.subject, util.format('props.subject is missing the encrypt key metadata @id', props));

  let payload = {};

  // add the metadata claim to the JWT payload
  payload[ENCRYPT_KEY_MD_CLAIM] = ekmd;

  return signPayload(payload, jwtOptions, props);
};

//
// Create a JWT that contains the following claims
// - a syndicate request claim
// - a subject_jwts claim
// - a privacy pipe claim
//
// *syndRequest - the jsonld syndicate request node - SYNDICATE_REQUEST_CLAIM
// *subjectJWTS - the array of subject JWTs - SUBJECT_JWTS_CLAIM
// *privacyPipeId - the privacy pipe Id used to send the JWT - PRIVACY_PIPE_CLAIM
// *jwtOptions - control the signing
// *props
//   subject: the syndRequest @id
//   issuer: comes from the jwtOptions
//
jwtUtils.signSyndicateRequest = function signSyndicateRequest(syndRequest, subjectJWTS, privacyPipeId, jwtOptions, props) {
  'use strict';
  assert(syndRequest, 'signSyndicateRequest syndRequest param missing');
  assert(subjectJWTS, 'signSyndicateRequest subjectJWTS param missing');
  assert(privacyPipeId, 'signSyndicateRequest privacyPipeId param missing');
  assert(props, 'signSyndicateRequest props param missing');
  assert(props.subject, util.format('signSyndicateRequest props.subject is missing the syndicate request @id', props));

  let payload = {};

  // add the claims to the JWT payload
  payload[SYNDICATE_REQUEST_CLAIM] = syndRequest;
  payload[SUBJECT_JWTS_CLAIM] = subjectJWTS;
  payload[PRIVACY_PIPE_CLAIM] = privacyPipeId;

  return signPayload(payload, jwtOptions, props);
};

//
// Create a JWT that contains the following claims
// - a subject claim - this contains a JSONLD node of type subject
//
// Note there is no privacy pipe claim as this JWT is under a syndicate
// request JWT. If has been obfuscated, then the pai information in the fields
// is enough to de-obfuscate
//
// *subject - the jsonld subject node
// *jwtOptions - control the signing
// *props
//   subject: the subject @id
//   issuer: comes from the jwtOptions
//
jwtUtils.signSubject = function signSubject(subject, jwtOptions, props) {
  'use strict';
  assert(subject, 'signSubject syndRequest param missing');
  assert(props, 'signSubject props param missing');
  assert(props.subject, util.format('signSubject props.subject is missing the subject @id', props));

  let payload = {};

  // add the claims to the JWT payload
  payload[SUBJECT_CLAIM] = subject;

  return signPayload(payload, jwtOptions, props);
};

//
// Create a JWT that contains a metadata claim. It can optionally contain
// a provision claim.
// *metadata - this is placed in the METADATA_CLAIM
// *jwtOptions - control the signing
// *props
//   subject: the metadata @id
//   issuer: comes from the jwtOptions
//   provision: optional provision claim
//
jwtUtils.signMetadata = function signMetadata(metadata, jwtOptions, props) {
  'use strict';
  assert(metadata, 'signMetadata metadata param missing');
  assert(props, 'signMetadata props param missing');

  // The metadata JWT payload must have a subject claim so check passed in.
  // Note the issuer is checked in lower levels as required.
  assert(props.subject, util.format('props.subject is missing the metadata @id', props));

  let payload = {};

  // add the metadata claim to the JWT payload
  payload[METADATA_CLAIM] = metadata;

  // if an optional provision claim then also add that
  if (props.provision) {
    payload[PROVISION_CLAIM] = props.provision;
  }

  return signPayload(payload, jwtOptions, props);
};

//
// Create a JWT that contains JUST a provision claim.
// *provision - this is placed in the PROVISION_CLAIM
// *jwtOptions - control the signing
// *props
//   subject: the provision @id
//   issuer: comes from the jwtOptions
//   privacyPipe: the privacy pipe @id associated with the provision.
//
jwtUtils.signProvision = function signProvision(provision, jwtOptions, props) {
  'use strict';
  assert(provision, 'signProvision provision param missing');
  assert(props, 'signProvision props param missing');

  // The provision JWT payload must have a subject claim so check passed in.
  // Note the issuer is checked in lower levels as required.
  assert(props.subject, util.format('props.subject is missing the provision @id', props));

  // The provision JWT payload must have a privacy pipe @id clam so check passed in.
  assert(props.privacyPipe, util.format('props.privacyPipe is missing the privacy pipe @id', props));

  let payload = {};
  payload[PROVISION_CLAIM] = provision;
  payload[PRIVACY_PIPE_CLAIM] = props.privacyPipe;

  return signPayload(payload, jwtOptions, props);
};

//
// Create JWT with private claims of
// pn_graph - data is placed in
// privacy_pipe - if pipe passed in then place in here
//
// Can also handle standard claim overrides in props
// subject
// issuer
//
// Returns a JWS serialized compact format of
// header.payload.signature.
//
// Can sign either h2256 or rs256
//
// *jwtOptions - set of params to control the jwt actions
// *graph: can be a jsonld graph, an array of objects, or an object
// @props: contains other properties
//  subject - place is the sub
//  issuer - override issuer in jwtOptions
//  privacyPipe - adds privacy pipe claim to the JWT
//
jwtUtils.signData = function signData(data, jwtOptions, props) {
  'use strict';
  assert(data, 'data param is missing');
  assert(jwtOptions, 'jwtOptions param missing');

  let payload = {};
  payload[PN_GRAPH_CLAIM] = data;

  // add privacy pipe claim
  if ((props) && (props.privacyPipe)) {
    payload[PRIVACY_PIPE_CLAIM] = props.privacyPipe;
  }

  return signPayload(payload, jwtOptions, props);
};

// verify a JWT - determine if should use the HS256 or RS256
jwtUtils.newVerify = function newVerify(token, jwtOptions) {
  'use strict';

  // decode the token so determine how to verify
  let decoded = jwtUtils.decode(token, { complete: true });

  if (decoded.header.alg === 'RS256') {
    return jwtUtils.verifyRS256(token, decoded);
  } else {
    return jwtUtils.verifyHS256(token, jwtOptions);
  }
};

//
// Decode the JWT but do not check the signature
// token - the token
// options
//   - json - if true for parse
//   - complete - if true returns a structure that has both header and payload
//
jwtUtils.decode = function decode(token, options) {
  'use strict';
  return jwt.decode(token, options);
};

//
// return the jsonld graph from inside the JWT
//
jwtUtils.getPnGraph = function getpnGraph(payload) {
  'use strict';
  return payload[PN_GRAPH_CLAIM];
};

//
// return the privacy pipe from inside the JWT
jwtUtils.getPrivacyPipe = function getPrivacyPipe(payload) {
  'use strict';
  return payload[PRIVACY_PIPE_CLAIM];
};

// OLD NOT DO USE
// Create a JWT wrapping data being send down a privacy pipe.
//
// The payload has the following private claims
// PN_GRAPH_CLAIM holds the data being sent
// PRIVACY_PIPE_CLAIM holds the pipe @id
//
// *jwtOptions - set of params to control the jwt actions
// *graph - JSON ld graph to send
// @props
//   props.privacyPipe
//
jwtUtils.signPipeData = function signPipeData(jwtOptions, graph, props) {
  'use strict';

  // The graph must have a top level @graph property - it can be a named or non named graph
  assert(graph, 'signPipeData graph param missing');
  assert(graph['@graph'], util.format('The passed in graph must have a top level @graph property:%j', graph));
  assert(props, 'signPipeData - props param missing');
  assert(props.privacyPipe, util.format('signPipeData - props.privacyPipe missing:%j', props));

  return jwtUtils.sign(jwtOptions, graph, props);
};

// OLD DO NOT USE
// Create a signed JWT returning a JWS serialized compact format of
// header.payload.signature.
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

  let payload = {};

  // add privacy pipe claim
  if ((props) && (props.privacyPipe)) {
    payload[PRIVACY_PIPE_CLAIM] = props.privacyPipe;
  }

  // add pn graph claim
  payload[PN_GRAPH_CLAIM] = graph;

  return signPayload(payload, jwtOptions, props);
};

// OLD CODE leave here until convert verify and unpack a JWT
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

// OLD DO NOT use
// convenience routine to verify and get the PnGraph - used if only need graph
jwtUtils.verifyGetPnGraph = function verifyGetPnGraph(jwtOptions, token) {
  'use strict';
  return jwtUtils.getPnGraph(
                  (jwtUtils.verify(jwtOptions, token)));
};

//------------------------
// private routines
//-----------------------

// verify JWT using RS256 and public key is included in the header
jwtUtils.verifyRS256 = function verifyRS256(token, decoded) {
  'use strict';

  // make sure the public key is in the header so can verify signature
  // note should check certificate but for now do not.
  //
  assert(decoded.header[HEADER_PUBLIC_KEY_PEM], util.format('%s is missing from the header',
          HEADER_PUBLIC_KEY_PEM, decoded.header));

  try {
    return jwt.verify(token, decoded.header[HEADER_PUBLIC_KEY_PEM]);
  } catch (err) {
    throw err;
  }
};

// verify JWT using HS256 using passed in secret
jwtUtils.verifyHS256 = function verifyHS256(token, jwtOptions) {
  'use strict';
  assert(jwtOptions, 'jwtOptions param missing');
  assert(jwtOptions.secret, util.format('jwtOptions.secret props missing:%j', jwtOptions));
  assert(token, util.format('token param to verify missing'));

  // note not checking the issuer or the subject
  try {
    return jwt.verify(token, jwtOptions.secret);
  } catch (err) {
    throw err;
  }
};

//
// Create a JWT using the passed in payload.
//
// Adds standard claims
// - issuer if passed in - required
// - subject if passed in - optional
//
// Handle RS256 signing when added public key and cert PEM to header
//
function signPayload(payload, jwtOptions, props) {
  'use strict';
  let localJwtOptions = {}; // make a copy so do not corrupt

  assert(payload, 'payload param missing');
  assert(jwtOptions, 'jwtOptions param missing');

  // check information needed for the iss claim is passed in - this is required
  if (jwtOptions.issuer) {
    localJwtOptions.issuer = jwtOptions.issuer;
  }

  // kind of wierd that can override must be a default somewhere
  if ((props) && (props.issuer)) {
    localJwtOptions.issuer = props.issuer;
  }

  assert(localJwtOptions.issuer, util.format('signPayload cannot find issuer in options:%j or props:%j', jwtOptions, props));

  // if a subject has been passed in then add to options so added to payload
  if ((props) && (props.subject)) {
    localJwtOptions.subject = props.subject;
  }

  //
  // check that specified the signing algorithm and necessary secret exist
  //
  assert(jwtOptions.type, util.format('jwtOptions.type props missing:%j', jwtOptions));

  switch (jwtOptions.type) {

    case 'HS256': {
      localJwtOptions.algorithm = 'HS256';
      assert(jwtOptions.secret, util.format('jwtOptions.secret props missing:%j', jwtOptions));
      return signUsingHS256(payload, jwtOptions.secret, localJwtOptions);
    }

    case 'RS256' : {
      localJwtOptions.algorithm = 'RS256';

      // add the public key PEM and x509 cert PEM to the header - merged into header
      let header = {};
      assert(jwtOptions.publicKeyPEM, util.format('jwtOptions.publicKeyPEM missing:%j', props));
      header[HEADER_PUBLIC_KEY_PEM] = jwtOptions.publicKeyPEM;

      assert(jwtOptions.x509CertPEM, util.format('jwtOptions.x509CertPEM missing:%j', props));
      header[HEADER_X509_CERT_PEM] = jwtOptions.x509CertPEM;
      localJwtOptions.header = header;

      assert(jwtOptions.privateKey, util.format('jwtOptions.privateKey missing:%j', props));
      return signUsingRS256(payload, jwtOptions.privateKey, localJwtOptions);
    }

    default: {
      assert(false, util.format('jwtOptions.type must be HS256 as only type supported:%j', jwtOptions));
    }

  }
}

//
// Sign using the HS256 algorithm
//
function signUsingHS256(payload, secret, jwtOptions) {
  'use strict';
  assert((jwtOptions.algorithm === 'HS256'), util.format('jwtOptions.algorithm must be HS256:%j', jwtOptions));
  assert(secret, 'secret param is missing');
  return jwt.sign(payload, secret, jwtOptions);
}

//
// Sign using the RS256 algorithm
//
function signUsingRS256(payload, secret, jwtOptions) {
  'use strict';
  assert((jwtOptions.algorithm === 'RS256'), util.format('jwtOptions.algorithm must be RS256:%j', jwtOptions));
  assert(secret, 'secret param is missing');
  return jwt.sign(payload, secret, jwtOptions);
}

module.exports = {
  jwtUtils: jwtUtils,

  // claim constants
  claims: {
    ENCRYPT_KEY_MD_CLAIM: ENCRYPT_KEY_MD_CLAIM,
    METADATA_CLAIM: METADATA_CLAIM,
    PN_GRAPH_CLAIM: PN_GRAPH_CLAIM,
    PRIVACY_PIPE_CLAIM: PRIVACY_PIPE_CLAIM,
    PROVISION_CLAIM: PROVISION_CLAIM,
    SYNDICATE_REQUEST_CLAIM: SYNDICATE_REQUEST_CLAIM,
    SUBJECT_JWTS_CLAIM: SUBJECT_JWTS_CLAIM,
    SUBJECT_CLAIM: SUBJECT_CLAIM,
  },
};
