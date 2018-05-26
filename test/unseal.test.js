/* global describe, it */

var fernet = require('fernet');
var setup = require('../lib/unseal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('unseal', function() {
  
  describe('using defaults', function() {
    
    describe('decrypting', function() {
      var claims, conditions;
      
      var keying = sinon.spy(function(entity, q, cb){
        if (q.usage == 'decrypt') {
          return cb(null, { secret: 'abcdef7890abcdef' });
        } else {
          return cb(null, { secret: 'API-12abcdef7890' });
        }
      });
      
      before(function(done) {
        var token = 'gAAAAABZQZ8EjPXNpNuS1P2retbZFG9yvR068ZRVdw2ba0JXJdrRxaqkuqKU5kgchw2So0T8HMBSowFnrjnyP4XFTOfHp-6ttg==';
        
        var unseal = setup(keying);
        unseal(token, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'decrypt',
          algorithms: [ 'aes128-cbc' ],
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ],
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting
    
    describe('decrypting with issuer', function() {
      var claims, conditions;
      
      var keying = sinon.spy(function(entity, q, cb){
        if (q.usage == 'decrypt') {
          return cb(null, { secret: 'abcdef7890abcdef' });
        } else {
          return cb(null, { secret: 'API-12abcdef7890' });
        }
      });
      
      before(function(done) {
        var token = 'gAAAAABZQZ8EjPXNpNuS1P2retbZFG9yvR068ZRVdw2ba0JXJdrRxaqkuqKU5kgchw2So0T8HMBSowFnrjnyP4XFTOfHp-6ttg==';
        
        var unseal = setup(keying);
        unseal(token, { issuer: { identifier: 'https://server.example.com' } }, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://server.example.com' });
        expect(call.args[1]).to.deep.equal({
          usage: 'decrypt',
          algorithms: [ 'aes128-cbc' ],
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://server.example.com' });
        expect(call.args[1]).to.deep.equal({
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ],
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar'
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // decrypting with issuer
    
  }); // using defaults
  
}); // unseal
