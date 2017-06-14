/* global describe, it */

var fernet = require('fernet');
var setup = require('../lib/unseal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('unseal', function() {
  
  describe('using defaults', function() {
    var unseal, keying;
    
    describe('unsealing', function() {
      before(function() {
        keying = sinon.spy(function(q, cb){
          return cb(null, [ { secret: 'API-12abcdef7890abcdef7890abcdef' } ]);
        });
      
        unseal = setup(keying);
      });
      
      var tkn;
      before(function(done) {
        var token = 'gAAAAABZQZ8EjPXNpNuS1P2retbZFG9yvR068ZRVdw2ba0JXJdrRxaqkuqKU5kgchw2So0T8HMBSowFnrjnyP4XFTOfHp-6ttg==';
        
        unseal(token, function(err, t) {
          tkn = t;
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
          usage: 'decrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ],
          length: 256
        });
      });
      
      it('should unseal token', function() {
        expect(tkn).to.be.an('object');
        expect(Object.keys(tkn)).to.have.length(2);
        
        expect(tkn).to.deep.equal({
          headers: {
          },
          claims: {
            foo: 'bar'
          }
        });
      });
    }); // unsealing
    
  });
  
});
