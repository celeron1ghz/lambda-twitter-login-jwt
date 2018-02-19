'use strict';

const TwitterOAuth = require('./lib/TwitterOAuth');

const jwt       = require('jsonwebtoken');
const vo        = require('vo');
const uniqid    = require('uniqid');
const Cookie    = require('cookie');
const aws       = require('aws-sdk');
const ssm       = new aws.SSM();
const dynamodb  = new aws.DynamoDB.DocumentClient();

module.exports.auth = (event, context, callback) => {
  return vo(function*(){
    const uid   = uniqid();
    const oauth = yield TwitterOAuth.createInstance(event);
    const auth  = yield oauth.getOAuthRequestToken();

    const ret = yield dynamodb.put({
      TableName: "twitter_oauth",
      Item: {
        uid: uid,
        ttl: (new Date().getTime() / 1000 + 60 * 24),
        session: auth.oauth_token_secret,
      },
    }).promise();

    return callback(null, {
      statusCode: 302,
      body:       '',
      headers:    {
        'Location': 'https://twitter.com/oauth/authenticate?oauth_token=' + auth.oauth_token,
        'Set-Cookie': 'sessid=' + uid + '; secure;',
      },
    });

  }).catch(err => {
    console.log("Error on auth:", err);
    return callback(null, { statusCode: 500, body: "ERROR!" });
  });
};

module.exports.callback = (event, context, callback) => {
  return vo(function*(){
    if (!event.headers.Cookie) {
      throw new Error("NO_DATA1");
    }

    const sessid = Cookie.parse(event.headers.Cookie || '').sessid;
    const row    = yield dynamodb.get({ TableName: "twitter_oauth", Key: { "uid": sessid } }).promise();

    if (!row.Item) {
      throw new Error("NO_DATA2");
    }

    const oauth = yield TwitterOAuth.createInstance(event);
    const oauth_token_secret = row.Item.session;

    const query = event.queryStringParameters;
    const ret = yield oauth.getOAuthAccessToken(query.oauth_token, oauth_token_secret, query.oauth_verifier);
    const me  = yield oauth.call_get_api(ret.access_token, ret.access_token_secret, "account/verify_credentials", {});

    console.log("OAUTH_SUCCESS:", me.screen_name, "(" + me.name + ")");

    yield dynamodb.put({
      TableName: "twitter_oauth",
      Item: {
        uid:               sessid,
        twitter_id:        me.id_str,
        screen_name:       me.screen_name,
        display_name:      me.name,
        profile_image_url: me.profile_image_url_https,
        ttl:               (new Date().getTime() / 1000 + 60 * 24 * 30),
      },
    }).promise();

    const secret = (yield ssm.getParameter({ Name: '/twitter_oauth/jwt_token', WithDecryption: true }).promise() ).Parameter.Value;
    const signed = jwt.sign({ sessid: sessid }, secret);

    return callback(null, {
      statusCode: 200,
      headers: { 'Content-Type': "text/html"},
      body: `<script>window.opener.postMessage("${signed}", "*"); window.close();</script>`,
    });
  }).catch(err => {
    return callback(null, { statusCode: 500, body: JSON.stringify({ error: err.message }) });
  });
};

module.exports.me = (event, context, callback) => {
  return vo(function*(){
    if (!event.headers.Authorization) {
      throw new Error("INVALID_HEADER1");
    }

    const token_matched = event.headers.Authorization.match(/^Bearer\s+(\w+\.\w+\.\w+)$/);

    if (!token_matched) {
      throw new Error("INVALID_HEADER2");
    }

    const token  = token_matched[1];
    const secret = (yield ssm.getParameter({ Name: '/twitter_oauth/jwt_token', WithDecryption: true }).promise() ).Parameter.Value;
    let sessid;

    try {
      const data = jwt.verify(token, secret);
      sessid = data.sessid;
    } catch(e) {
      console.log("Error on jwt verify:", e.toString());
      throw new Error("INVALID_HEADER3");
    }
    const ret = yield dynamodb.get({
      TableName: "twitter_oauth",
      Key: { "uid": sessid },
      AttributesToGet: ['twitter_id', 'screen_name', 'display_name', 'profile_image_url']
    }).promise();

    const row = ret.Item;

    if (!row) {
      throw new Error("DATA_NOT_EXIST1");
    }

    if (!row.twitter_id) {
      throw new Error("DATA_NOT_EXIST2");
    }

    return callback(null, {
      statusCode: 200,
      headers: {
        //'Access-Control-Allow-Origin': process.env.TWITTER_OAUTH_ORIGIN_URL,
        'Access-Control-Allow-Origin': event.headers.origin,
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify(row),
    });

  }).catch(err => {
    return callback(null, { statusCode: 500, body: JSON.stringify({ error: err.message }) });
  });
};