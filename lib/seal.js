var fernet = require('fernet');


/**
 * Seal a security token in a fernet envelope.
 *
 * Fernet is a message security format that provides encryption with integrity
 * protection of JSON data structures.  The encryption is conducted using
 * AES-128 in CBC mode with integrity provided by a SHA-256 HMAC.
 *
 * Due to the fact that symmetric encryption is utilized, it is not necessary
 * to indicate the intended audience within the token itself.  The secret shared
 * between the issuer and the audience is sufficient to prove that the token
 * has been received by the intended party, provided that the token is indeed
 * valid.
 *
 * References:
 *  - [Fernet Spec](https://github.com/fernet/spec/blob/master/Spec.md)
 */
module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function fernet_seal(claims, recipients, options, cb) {
    if (!Array.isArray(recipients)) {
      recipients = [ recipients ];
    }
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    if (recipients.length > 1) {
      return cb(new Error('Unable to seal fernet tokens to multiple recipients'));
    }
    
   
    function proceed(encryptionKey, signingKey) {
      // TODO: Other payload formats (messagepack, etc)
      var payload = JSON.stringify(claims);
      
      // first 128 bits for HMAC SHA256 signing key; last 128 bits for AES-128 encryption key
      var key = signingKey.secret + encryptionKey.secret;
      var secret = new fernet.Secret(Buffer.from(key, 'utf8').toString('base64'));
      var token = new fernet.Token({ secret: secret });
      token.encode(payload);
      
      return cb(null, token.toString());
    }
    
    // NOTE: Fernet makes use of HMAC SHA256 for message authentication.
    //       However, it uses a 128-bit key for signing operations, less than
    //       the recommended length of 256 bits.
    //
    //       More information can be found here:
    //       - https://github.com/fernet/spec/issues/8
    //       - https://github.com/pyca/cryptography/issues/2863
    var query  = {
      usage: 'encrypt',
      recipient: recipients[0],
      algorithms: [ 'aes128-cbc' ]
    }
    
    keying(recipients[0], query, function(err, encryptionKeys) {
      if (err) { return cb(err); }
      
      var key = encryptionKeys;
      if (key.usages && key.usages.indexOf('sign') !== -1) {
        // The encryption key also allows usage for signing operations.  Proceed
        // to use the same key for both encryption and signing.
        return proceed(key, key);
      }
      
      // The encryption key has been obtained, query for the signing key.
      var query  = {
        usage: 'sign',
        recipient: recipients[0],
        algorithms: [ 'hmac-sha256' ]
      }
      
      keying(recipients[0], query, function(err, signingKey) {
        if (err) { return cb(err); }
        return proceed(key, signingKey);
      });
    });
  };
};
