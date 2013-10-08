/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 */

var EventEmitter = require('events').EventEmitter,
     querystring = require('querystring'),
      serializer = require('serializer');

_extend = function(dst,src) {

  var srcs = [];
  if ( typeof(src) == 'object' ) {
    srcs.push(src);
  } else if ( typeof(src) == 'array' ) {
    for (var i = src.length - 1; i >= 0; i--) {
      srcs.push(this._extend({},src[i]))
    };
  } else {
    throw new Error("Invalid argument")
  }

  for (var i = srcs.length - 1; i >= 0; i--) {
    for (var key in srcs[i]) {
      dst[key] = srcs[i][key];
    }
  };

  return dst;
}
function parse_authorization(authorization) {
  if(!authorization)
    return null;

  var parts = authorization.split(' ');

  if(parts.length != 2 || parts[0] != 'Basic')
    return null;

  var creds = new Buffer(parts[1], 'base64').toString(),
          i = creds.indexOf(':');

  if(i == -1)
    return null;

  var username = creds.slice(0, i);
      password = creds.slice(i + 1);

  return [username, password];
}

function OAuth2Provider(options) {
  if(arguments.length != 1) {
    console.warn('OAuth2Provider(crypt_key, sign_key) constructor has been deprecated, yo.');

    options = {
      crypt_key: arguments[0],
      sign_key: arguments[1],
    };
  }

  options['authorize_uri'] = options['authorize_uri'] || '/oauth/authorize';
  options['access_token_uri'] = options['access_token_uri'] || '/oauth/access_token';

  this.options = options;
  this.serializer = serializer.createSecureSerializer(this.options.crypt_key, this.options.sign_key);
}

OAuth2Provider.prototype = new EventEmitter();

OAuth2Provider.prototype.generateAccessToken = function(user_id, client_id, extra_data, token_options) {
  token_options = token_options || {}
  var out = _extend(token_options, {
    access_token: this.serializer.stringify([user_id, client_id, +new Date, extra_data]),
    refresh_token: null,
  });
  return out;
};

OAuth2Provider.prototype.login = function() {
  var self = this;

  return function(req, res, next) {
    var data, atok, user_id, client_id, grant_date, extra_data;

    if(req.query['access_token']) {
      atok = req.query['access_token'];
    } else if((req.headers['authorization'] || '').indexOf('Bearer ') == 0) {
      atok = req.headers['authorization'].replace('Bearer', '').trim();
    } else {
      return next();
    }

    try {
      data = self.serializer.parse(atok);
      user_id = data[0];
      client_id = data[1];
      grant_date = new Date(data[2]);
      extra_data = data[3];
    } catch(e) {
      res.writeHead(400);
      return res.end(e.message);
    }

    self.emit('access_token', req, {
      user_id: user_id,
      client_id: client_id,
      extra_data: extra_data,
      grant_date: grant_date
    }, next);
  };
};

OAuth2Provider.prototype.oauth = function() {
  var self = this;
  return function(req, res, next) {
    var uri = ~req.url.indexOf('?') ? req.url.substr(0, req.url.indexOf('?')) : req.url;
    if(req.method == 'POST' && '/oauth/authorize' == uri) {
      var client_id = req.body.client_id,
          code = serializer.randomString(128);
      self.emit('save_grant', req, client_id, code, function() {
        var extras = {
          code: code,
        };
        res.send({'request_token': code});
      });
    } else if(req.method == 'POST' && '/oauth/access_token' == uri) {
      var client_id = req.body.client_id,
          client_secret = req.body.client_secret,
          code = req.body.code;
      self.emit('lookup_grant', client_id, client_secret, code, function(err, user_id) {
        if (err) {
          res.writeHead(400);
          return res.end(err.message);
        }
        res.writeHead(200, {'Content-type': 'application/json'});
        self.emit('create_access_token', user_id, client_id, function(extra_data) {
          var atok = self.generateAccessToken(user_id, client_id, extra_data);
          if (self.listeners('save_access_token').length > 0) {
            self.emit('save_access_token', user_id, client_id, atok);
          }
          res.end(JSON.stringify(self.generateAccessToken(user_id, client_id, extra_data)));
        });
        self.emit('remove_grant', user_id, client_id, code);
      });
    } else {
      return next();
    }
  };
};

exports.OAuth2Provider = OAuth2Provider;
