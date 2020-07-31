var fernet = require('fernet');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('defaults', function() {
    
    describe('encrypting to self', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        switch (q.usage) {
        case 'encrypt':
          return cb(null, { secret: 'ef7890abcdef7890' });
        case 'sign':
          return cb(null, { secret: '12abcdef7890abcd' });
        }
      });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ beep: 'boop' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt',
          algorithms: [ 'aes-128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token).to.be.a('string');
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var s = new fernet.Secret(Buffer.from('12abcdef7890abcdef7890abcdef7890', 'utf8').toString('base64'));
          var t = new fernet.Token({ token: token, secret: s, ttl: 0 });
          var payload = t.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.deep.equal({
            beep: 'boop'
          });
        });
      });
    }); // encrypting to self
    
    describe('encrypting to recipient', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        switch (q.usage) {
        case 'encrypt':
          return cb(null, { secret: 'abcdef7890abcdef', usages: [ 'encrypt' ] });
        case 'sign':
          return cb(null, { secret: 'API-12abcdef7890', usages: [ 'sign' ] });
        }
      });
      
      before(function(done) {
        var recipients = [ 'https://api.example.com/' ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, recipients, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        
        var call = keying.getCall(0);
        expect(call.args[0]).to.equal('https://api.example.com/');
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt',
          algorithms: [ 'aes-128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal('https://api.example.com/');
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token).to.be.a('string');
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var s = new fernet.Secret(Buffer.from('API-12abcdef7890abcdef7890abcdef', 'utf8').toString('base64'));
          var t = new fernet.Token({ token: token, secret: s, ttl: 0 });
          var payload = t.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.deep.equal({
            beep: 'boop'
          });
        });
      });
    }); // encrypting to recipient
    
    describe('encrypting to recipient using single secret for both encryption and signing', function() {
      var token;
      
      var keying = sinon.spy(function(entity, q, cb){
        return cb(null, { secret: 'NET-12abcdef7890', usages: [ 'sign', 'encrypt' ] });
      });
      
      before(function(done) {
        var audience = [ 'https://api.example.net/' ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, audience, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        
        var call = keying.getCall(0);
        expect(call.args[0]).to.equal('https://api.example.net/');
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt',
          algorithms: [ 'aes-128-cbc' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token).to.be.a('string');
        expect(token.length).to.equal(100);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var s = new fernet.Secret(Buffer.from('NET-12abcdef7890NET-12abcdef7890', 'utf8').toString('base64'));
          var t = new fernet.Token({ token: token, secret: s, ttl: 0 });
          var payload = t.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be valid', function() {
          expect(claims).to.deep.equal({
            beep: 'boop'
          });
        });
      });
    }); // encrypting to recipient using single secret for both encryption and signing
    
    describe('encrypting to multiple recipients', function() {
      var error, token;
      
      before(function(done) {
        var recipients = [
          'https://api.example.com/',
          'https://api.example.net/'
        ];
        
        var seal = setup(function(){});
        seal({ beep: 'boop' }, recipients, function(err, t) {
          error = err;
          token = t;
          done();
        });
      });
      
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Unable to seal fernet token to multiple recipients');
      });
      
      it('should not generate a token', function() {
        expect(token).to.be.undefined;
      });
    }); // encrypting to multiple recipients
    
  }); // defaults
  
}); // seal
