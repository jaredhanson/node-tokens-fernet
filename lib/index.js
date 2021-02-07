var fernet = require('fernet')
  , base64url = require('base64url');


/**
 * Fernet token implementation.
 *
 * This package implements support for serializing and deserializing claims into
 * and out of [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) tokens.
 *
 * Fernet is a rather obscure token format, originally developed at [Heroku](https://www.heroku.com/)
 * and later having been notably adopted by [OpenStack](https://www.openstack.org/)
 * [Keystone](https://docs.openstack.org/developer/keystone/).
 *
 * Use of Fernet by Heroku appears to have been first publicly documented in an
 * [article](https://engineering.heroku.com/blogs/2014-09-15-securing-celery/)
 * describing its use to secure jobs distributed via [Celery](http://www.celeryproject.org/).
 * Note that the payload of a Fernet token can be serialized in various formats,
 * and Heroku appears to have implementations using JSON, YAML, MessagePack, and
 * pickle.
 *
 * The adoption of Fernet by OpenStack was described in an [article](http://dolphm.com/openstack-keystone-fernet-tokens/)
 * by [Dolph Mathews](http://dolphm.com/) giving an overview of their benefits
 * and contents.  Mr. Mathews has also written other articles further detailing
 * Fernet token [payloads](http://dolphm.com/inside-openstack-keystone-fernet-token-payloads/),
 * [benchmarks](http://dolphm.com/benchmarking-openstack-keystone-token-formats/),
 * and [comparisons](http://dolphm.com/the-anatomy-of-openstack-keystone-token-formats/)
 * to other token formats used within OpenStack.  It should be noted that the
 * payload of a Fernet token as used within OpenStack is serialized using
 * MessagePack.
 *
 * Further relevant commentary about the nature of Fernet tokens, as used within
 * OpenStack, can be found at the following locations:
 *
 *     - https://developer.ibm.com/opentech/2015/11/11/deep-dive-keystone-fernet-tokens/
 *     - http://lbragstad.com/fernet-tokens-and-key-rotation/
 *     - http://lbragstad.com/fernet-tokens-and-key-distribution/
 *     - http://www.mattfischer.com/blog/?p=648
 *
 * For a period of time, Fernet tokens were referred to within OpenStack as
 * Keystone Lightweight Tokens (KLWT).  Further information about such tokens can
 * be found at the following locations:
 *
 *     - https://docs.openstack.org/admin-guide/identity-tokens.html
 *     - https://docs.openstack.org/admin-guide/identity-fernet-token-faq.html
 *     - https://specs.openstack.org/openstack/keystone-specs/specs/kilo/klwt.html
 *
 * Many thanks are owed to [Chad Whitacre](http://whit537.org/) for his
 * extensive [research](https://github.com/gratipay/gratipay.com/pull/3998) on
 * Fernet when implementing symmetric encryption in [Gratipay](https://gratipay.com/).
 * The entire discussion on that pull request is in itself an invaluble resource
 * that aids in understanding the considerations necessary when choosing a
 * cryptographic implementation.
 *
 * I originally discovered this token format via [Scott Arciszewski](https://twitter.com/CiPHPerCoder),
 * who published an [article](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)
 * about why JWTs should be avoided.  I don't fully agree with all the
 * statements made in the article.  However, Fernet is nonetheless a valid and
 * simpler alternative to JWT for certain use cases.
 */

exports.seal = require('./seal');
exports.unseal = require('./unseal');

exports.parse = function(token) {
  var b = base64url.toBuffer(token);
  return b[0] == 0x80;
}

