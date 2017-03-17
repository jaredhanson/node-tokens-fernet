var fernet = require('fernet');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (q.recipients) {
          var recipient = q.recipients[0];
          return cb(null, [ { secret: recipient.secret } ]);
        }
        
        return cb(null, [ { id: 'k1', secret: '12abcdef7890abcdef7890abcdef7890' } ]);
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting arbitrary claims', function() {
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
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: undefined,
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ],
          length: 256
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function() {
          var fsecret = new fernet.Secret(Buffer.from('12abcdef7890abcdef7890abcdef7890', 'utf8').toString('base64'));
          var ftoken = new fernet.Token({ token: token, secret: fsecret, ttl: 0 });
          var payload = ftoken.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting arbitrary claims
    
    describe('encrypting arbitrary claims to audience', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: [ {
            id: 'https://api.example.com/',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          } ],
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ],
          length: 256
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 1)).to.equal('g');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function() {
          var fsecret = new fernet.Secret(Buffer.from('API-12abcdef7890abcdef7890abcdef', 'utf8').toString('base64'));
          var ftoken = new fernet.Token({ token: token, secret: fsecret, ttl: 0 });
          var payload = ftoken.decode();
          
          claims = JSON.parse(payload);
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting arbitrary claims
    
  });
  
});
