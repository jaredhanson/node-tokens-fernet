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
 * valid and the secret is not shared with any other parties.
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
  
  
  return function fernet_seal(claims, options, cb) {
    //if (Array.isArray(options)) {
    //  options = { recipients: options };
    //}
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var recipients = options.recipients || [];
    if (recipients.length > 1) {
      return cb(new Error('Unable to seal fernet token to multiple recipients'));
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
    
    
    if (Array.isArray(options)) {
      console.log('ARRAY');
      
      return proceed(options[0], options[1]);
    }
    
    if (options.secret) {
      console.log('WHOLE SECRET');
      return proceed({ secret: options.secret.slice(16) }, { secret: options.secret.slice(0, 16) });
    }
    
    var query  = {
      usage: 'encrypt',
      algorithms: [ 'aes-128-cbc' ]
    }
    keying(recipients[0], query, function(err, key) {
      if (err) { return cb(err); }
      
      if (key.usages && key.usages.indexOf('sign') !== -1) {
        // The encryption key also allows usage for signing operations.  Proceed
        // to use the same key for both encryption and signing.
        return proceed(key, key);
      }
      
      // NOTE: Fernet makes use of HMAC SHA256 for message authentication.
      //       However, it uses a 128-bit key for signing operations, less than
      //       the recommended length of 256 bits.
      //
      //       More information can be found here:
      //       - https://github.com/fernet/spec/issues/8
      //       - https://github.com/pyca/cryptography/issues/2863
      var query  = {
        usage: 'sign',
        algorithms: [ 'sha256' ]
      }
      keying(recipients[0], query, function(err, signingKey) {
        if (err) { return cb(err); }
        return proceed(key, signingKey);
      });
    });
  };
};
