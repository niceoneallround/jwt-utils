
Provides JWT utils that are used inside the Privacy Network.

The adds the following custom properties to a JWT
 - https://pn.schema.webshield.io/prop#pn_graph - holds a JSON-LD graph
 - https://pn.schema.webshield.io/prop#privacy_pipe' - optional and holds the privacy pipe @id

It provides the following options for creating a JWT
 - issuer - the issuer and placed in the payload.iss property
 - type - the type of signing that should be used, only supports HS256 for now
 - secret - the secret that should be used for signing
 - subject - optional - the subject of the JWY placed in payload.sub property
 - privacy_pipe - optional - the @id of a privacy pipe that needs to be associated with the operation in pn_p.privacy_pipe
 - graph - the @graph to be placed in the pn_p.pn_graph property.

It uses the following node module
 - https://github.com/auth0/node-jsonwebtoken

It provides utils
 - sign - creates a JWT from passed in properties
 - verify - verifies the JWT signature and returns the payload
 - verifyGetPnGraph - verifies the JWT signature, returns payload[https://pn.schema.webshield.io/prop#pn_graph]
 - getPnGraph returns payload[https://pn.schema.webshield.io/prop#pn_graph]
 - getPivacyPipe returns payload[https://pn.schema.webshield.io/prop#privacy_pipe];
