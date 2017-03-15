var fernet = require('fernet')


module.exports = function(options, keying) {
  
  return function fernet_unseal(t, cb) {
    console.log('UNSEAL FERNET!');
    console.log(t);
    
    
    var query  = {
      recipients: options.audience,
      usage: 'decrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 32
    }
    
    keying(query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);
      
      if (err) { return cb(err); }
      
      var key = keys[0];
      
      var secret = new fernet.Secret(Buffer.from(key.secret, 'utf8').toString('base64'));
      var token = new fernet.Token({ token: t, secret: secret, ttl: 0 });
      var payload = token.decode();
      
      console.log(payload);
      
      // TODO: Other payload formats (messagepack, etc)
      var claims = JSON.parse(payload);
      
      var tok = {
        issuer: query.sender,
        headers: {
          issuer: claims.iss
        },
        claims: claims
      }
    
      return cb(null, tok);
    });
  };
};
