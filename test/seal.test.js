var fernet = require('fernet');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;

    before(function() {
      keying = sinon.spy(function(q, cb){
        if (!q.recipient) {
          if (q.usage == 'encrypt') {
            return cb(null, [ { secret: 'ef7890abcdef7890' } ]);
          } else {
            return cb(null, [ { secret: '12abcdef7890abcd' } ]);
          }
        }

        switch (q.recipient.id) {
        case 'https://api.example.com/':
          if (q.usage == 'encrypt') {
            return cb(null, [ { secret: 'abcdef7890abcdef', usages: [ 'encrypt' ] } ]);
          } else {
            return cb(null, [ { secret: 'API-12abcdef7890', usages: [ 'sign' ] } ]);
          }
          break;
          
        case 'https://api.example.net/':
          return cb(null, [ { secret: 'NET-12abcdef7890', usages: [ 'sign', 'encrypt' ] } ]);
        }
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting to self', function() {
      var token;
      before(function(done) {
        seal({ foo: 'bar' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: undefined,
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          recipient: undefined,
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var fsecret = new fernet.Secret(Buffer.from('12abcdef7890abcdef7890abcdef7890', 'utf8').toString('base64'));
          var ftoken = new fernet.Token({ token: token, secret: fsecret, ttl: 0 });
          var payload = ftoken.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to audience', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var fsecret = new fernet.Secret(Buffer.from('API-12abcdef7890abcdef7890abcdef', 'utf8').toString('base64'));
          var ftoken = new fernet.Token({ token: token, secret: fsecret, ttl: 0 });
          var payload = ftoken.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience
    
    describe('encrypting to audience using single key for both encryption and message authentication', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.net/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.net/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var fsecret = new fernet.Secret(Buffer.from('NET-12abcdef7890NET-12abcdef7890', 'utf8').toString('base64'));
          var ftoken = new fernet.Token({ token: token, secret: fsecret, ttl: 0 });
          var payload = ftoken.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience implicitly single key for both encryption and message authentication
    
  }); // using defaults
  
}); // seal
