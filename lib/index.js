// https://github.com/fernet/spec/issues/15
// https://github.com/gratipay/gratipay.com/pull/3998

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
 * describing its use to secure jobs distributed via [Celery](http://www.celeryproject.org/)
 *
 * I originally discovered this token format via [Scott Arciszewski](https://twitter.com/CiPHPerCoder),
 * who published an [article](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)
 * about why JWTs should be avoided.  I don't fully agree with all the
 * statements made in the article.  However, Fernet is nonetheless a valid and
 * simpler alternative to JWT.
 */
exports.seal = require('./seal');
exports.unseal = require('./unseal');
