var fernet = require('fernet');


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function fernet_seal(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    // Fernet tokens use AES encryption in CBC mode with a SHA-256 HMAC.  This
    // is a symmetric key algorithm, requiring the recipient to have a shared
    // secret with issuer of the token.
    //
    // The JWS `enc` value for specifying this algorithm is `A128CBC-HS256`.
    //
    // There is no registered XML security URI for this construction; however,
    // the following two are relevant:
    //     - 2001/04/xmldsig-more#hmac-sha256
    //     - 2001/04/xmlenc#aes128-cbc
    //
    // The normalized algorithm identifier is a combination of those:
    // `aes128-cbc-hmac-sha256`.
    
    // NOTE: Fernet makes use of HMAC SHA256 for message authentication.
    //       However, it uses a 128-bit key for signing operations, less than
    //       the recommended length of 256 bits.
    //
    //       More information can be found here:
    //       - https://github.com/fernet/spec/issues/8
    //       - https://github.com/pyca/cryptography/issues/2863
    var query  = {
      recipients: options.audience,
      usage: 'encrypt',
      algorithms: [ 'aes128-cbc-hmac-sha256' ],
      length: 256 // first 128 bits for HMAC SHA256 signing key; last 128 bits for AES-128 encryption key
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      var key = keys[0];
      // TODO: Other payload formats (messagepack, etc)
      var payload = JSON.stringify(claims);
      
      var secret = new fernet.Secret(Buffer.from(key.secret, 'utf8').toString('base64'));
      var token = new fernet.Token({ secret: secret });
      token.encode(payload);
      
      return cb(null, token.toString());
    });
  };
};
