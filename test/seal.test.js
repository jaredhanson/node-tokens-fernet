var fernet = require('fernet');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('defaults', function() {
    
    describe('encrypting to self', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        if (q.usage == 'encrypt') {
          return cb(null, { secret: 'ef7890abcdef7890' });
        } else {
          return cb(null, { secret: '12abcdef7890abcd' });
        }
      });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ foo: 'bar' }, { identifier: 'https://self-issued.me' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://self-issued.me' });
        expect(call.args[1]).to.deep.equal({
          recipient: { identifier: 'https://self-issued.me' },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://self-issued.me' });
        expect(call.args[1]).to.deep.equal({
          recipient: { identifier: 'https://self-issued.me' },
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
    
    describe('encrypting to recipient', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        if (q.usage == 'encrypt') {
          return cb(null, { secret: 'abcdef7890abcdef', usages: [ 'encrypt' ] });
        } else {
          return cb(null, { secret: 'API-12abcdef7890', usages: [ 'sign' ] });
        }
      });
      
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ foo: 'bar' }, audience, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
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
    }); // encrypting to recipient
    
    describe('encrypting to audience using single key for both encryption and message authentication', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        return cb(null, { secret: 'NET-12abcdef7890', usages: [ 'sign', 'encrypt' ] });
      });
      
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.net/'
        } ];
        
        var seal = setup(keying);
        seal({ foo: 'bar' }, audience, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.net/'
        });
        expect(call.args[1]).to.deep.equal({
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
    }); // encrypting to audience using single key for both encryption and message authentication
    
    describe('encrypting to multiple recipients', function() {
      var error, token;
      
      before(function(done) {
        var recipients = [ {
          id: 'https://api.example.com/'
        }, {
          id: 'https://api.example.net/'
        } ];
        
        var seal = setup(function(){});
        seal({ foo: 'bar' }, recipients, function(err, t) {
          error = err;
          token = t;
          done();
        });
      });
      
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Unable to seal fernet tokens to multiple recipients');
      });
      
      it('should not generate a token', function() {
        expect(token).to.be.undefined;
      });
    }); // encrypting to multiple recipients
    
  }); // defaults
  
}); // seal
