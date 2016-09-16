
Provides JWT utils that are used inside the Privacy Network.

Private claims that can be added to the payload
 - https://pn.schema.webshield.io/prop#metadata - holds metadata claims
   - note the whole JWT is needed to create JSON-LD metadata node - for example sub is the @id
 - https://pn.schema.webshield.io/prop#pn_graph - holds subject data in a JSON-LD graph
 - https://pn.schema.webshield.io/prop#privacy_pipe' - optional and holds the privacy pipe @id

Standard claims
 - iss required
 - sub (optional)
 - exp (optional)
 - iat added

Signing
  - HS256 shared secret is passed in
  - RS256 so add PEM files to the JWT for verification the following header props are used
    - http://pn.schema.webshield.io/prop#jwk_pem - holds the public key PEM
    - http://pn.schema.webshield.io/prop#x5c_pem - holds an array with the x509cert PEM for the public key.

It uses the following node module
 - https://github.com/auth0/node-jsonwebtoken


Example JWT showing just the header and payload.

{ header: {
    "alg": "RS256",
    "typ": "JWT",
    "http://pn.schema.webshield.io/prop#jwk_pem": 'public key pem',
    "http://pn.schema.webshield.io/prop#x5c_pem": [ 'x509cert pem']
  },
  payload: {
    "iss": "abc.xom",
    "sub": "http://md.pn.id.webshield.io/resource/xom/abc#1",
    "https://pn.schema.webshield.io/prop#metadata: {}
  }
}
