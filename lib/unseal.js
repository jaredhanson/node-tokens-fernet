var fernet = require('fernet')


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function fernet_unseal(sealed, cb) {
    var query  = {
      usage: 'decrypt',
      algorithms: [ 'aes128-cbc-hmac-sha256' ],
      length: 256 // first 128 bits for HMAC SHA256 signing key; last 128 bits for AES-128 encryption key
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // TODO: Iterate over all keys, in order to support key rotation
      var key = keys[0];
      
      var secret = new fernet.Secret(Buffer.from(key.secret, 'utf8').toString('base64'));
      var token = new fernet.Token({ token: sealed, secret: secret, ttl: 0 });
      var payload = token.decode();
      
      // TODO: Other payload formats (messagepack, etc)
      var claims = JSON.parse(payload);
      
      var tkn = {
        headers: {
        },
        claims: claims
      }
    
      return cb(null, tkn);
    });
  };
};
