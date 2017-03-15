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
    
    console.log('SEAL AS FERNET');
    
    var query  = {
      recipients: options.audience,
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 32
    }
    
    keying(query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);

      if (err) { return cb(err); }
      
      var key = keys[0];
      // TODO: Other payload formats (messagepack, etc)
      var message = JSON.stringify(claims);
      
      var secret = new fernet.Secret(Buffer.from(key.secret, 'utf8').toString('base64'));
      console.log('FERNET:');
      console.log(secret);
      
      var token = new fernet.Token({ secret: secret });
      token.encode(message);
      
      console.log(token.toString());
      
      return cb(null, token.toString());
      
    });
  };
};
