var fernet = require('fernet')
  , base64url = require('base64url');

var internals = {};


/**
 * Unseal a security token from a fernet envelope.
 *
 * Fernet is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * AES-128 in CBC mode with integrity provided by a SHA-256 HMAC.
 *
 * Fernet tokens do not provide a standardized means of indicating the issuer
 * of a token.  As such, it is assumed that the receipient of a fernet token
 * has a pre-arranged relationship with a single trusted issuer with which
 * it shares an encryption and/or signing secrets used to decrypt and verify
 * tokens.
 *
 * Fernet tokens also do not provide a standardized means of indicating the
 * key which was used to encrypt and/or HMAC the token.  As such, multiple keys
 * may be viable options for verifying the token when rotation is occuring.  In
 * such cases, the token is considered valid if any of the keys are suitable.
 *
 * References:
 *  - [Fernet Spec](https://github.com/fernet/spec/blob/master/Spec.md)
 */
module.exports = function(options, keying) {
  if (typeof options == 'string') {
    options = { issuer: options };
  }
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  var issuer = options.issuer;
  
  
  return function fernet_unseal(sealed, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    if (!internals.isFernet(sealed)) {
      // not a fernet token
      return cb(null);
    }
    
    
    function proceed(encryptionKey, signingKey) {
      // first 128 bits for HMAC SHA256 signing key; last 128 bits for AES-128 encryption key
      var key = signingKey.secret + encryptionKey.secret;
      
      var secret = new fernet.Secret(Buffer.from(key, 'utf8').toString('base64'));
      var token = new fernet.Token({ token: sealed, secret: secret, ttl: 0 });
      var payload = token.decode();
      
      // TODO: Other payload formats (messagepack, etc)
      var claims = JSON.parse(payload);
      
      var conditions = {};
      // TODO: Put exiresAt on conditions
      
      return cb(null, claims, conditions);
    }
    
    if (Array.isArray(options)) {
      console.log('ARRAY');
      
      return proceed(options[0], options[1]);
    }
    
    if (options.secret) {
      console.log('WHOLE SECRET');
      return proceed({ secret: options.secret.slice(16) }, { secret: options.secret.slice(0, 16) });
    }
    
    var query  = {
      usage: 'decrypt',
      algorithms: [ 'aes-128-cbc' ]
    }
    keying(issuer, query, function(err, key) {
      if (err) { return cb(err); }
      
      // The decryption keys have been obtained, query for the verification keys.
      var query  = {
        usage: 'verify',
        algorithms: [ 'sha256' ]
      }
      keying(issuer, query, function(err, signingKey) {
        if (err) { return cb(err); }
        return proceed(key, signingKey);
      });
    });
  };
};


internals.isFernet = function(sealed) {
  var b = base64url.toBuffer(sealed);
  return b[0] == 0x80;
}
