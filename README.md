
Used to create the JWTs produced by the Privacy Network.

The JWT payloads contain JSON LD information and have the following format

- standard claims
  - iss the issuer - is a typed value and may contain: cnames, address, or other
  - sub the @id of item
  - iat - time issued
  - exp (optional)

- common private claims
  - https://pn.schema.webshield.io/prop#jwt_type - the JWT type

- private claims that are specific to the JWT type
  - see the jwtUtils file for these.

Signing
  - RS256 so add PEM files to the JWT for verification the following header props are used
    - http://pn.schema.webshield.io/prop#jwk_pem - holds the public key PEM
    - http://pn.schema.webshield.io/prop#x5c_pem - holds the x509cert PEM for the public key and bound identity. Can be used to validate
  - HS256 shared secret is passed in

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

Generating the keys and certs for the RS256 keys - key is 2048

openssl genrsa 2048 > rsa-private.pem
openssl rsa -in rsa-private.pem -pubout > rsa-public.pem
openssl req -new -key rsa-private.pem -out rsa.csr
openssl x509 -req -days 1000 -in rsa.csr -signkey rsa-private.pem -out rsa.x509crt -extfile rsa.ext


1. generate a private key
  1.a openssl genrsa 2048 > rsa-private.pem
  1.b look at key openssl rsa  -in rsa-private.pem -noout -text
2. generate public key
  2.a openssl rsa -in rsa-private.pem -pubout > rsa-public.pem
  2.b look at it more rsa-public.pem
3. Generate a certificate signing request (CSR) - note don't need for a self signing but hey
  3.a openssl req -new -key rsa-private.pem -out rsa.csr
  3.b look at openssl req -text -in rsa.csr -noout
4. Self sign the certificate - using an extension file to specify the names
  4.a create rsa.ext - note all are here as ssytems may not sure the cname
       subjectAltName = DNS:sv.mds.webshield.io, DNS:sv-1.mds.webshield.io
  4.b openssl x509 -req -days 365 -in rsa.csr -signkey rsa-private.pem -out rsa.x509crt -extfile rsa.ext
5. Examine the certificate
  5.a openssl x509 -text -in rsa.x509crt -noout
