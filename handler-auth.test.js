'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

describe('/auth test', () => {
  const callback = (error, result) => new Promise((resolve, reject) => {
    error ? reject(error) : resolve(result)
  });

  let lambda;
  let proxyDynamoDB;
  let proxyOAuth;

  beforeEach(() => {
    proxyOAuth = class { createInstance () {} };
    proxyDynamoDB = class { put () {} };

    lambda = proxyquire('./handler', {
      'aws-sdk': { DynamoDB: { DocumentClient: proxyDynamoDB } },
      "./lib/TwitterOAuth":  proxyOAuth,
    });
  });


  it('ok', () => {
    sinon.stub(proxyDynamoDB.prototype, 'put').returns({  promise: () => Promise.resolve(null)  });
    sinon.stub(proxyOAuth, 'createInstance').returns(
      Promise.resolve({
        getOAuthRequestToken: () => Promise.resolve({
          oauth_token: "oauth_token", oauth_token_secret: "oauth_sec", results: {}
        })
      })
    );

    return expect(lambda.auth({}, {}, callback)).to.be.fulfilled.then(result => {
      const cookie = result.headers['Set-Cookie'];
      delete result.headers['Set-Cookie']

      expect(cookie).to.match(/^sessid=\w+; secure;$/);
      expect(result).to.deep.equal({
        statusCode: 302,
        headers: { Location: "https://twitter.com/oauth/authenticate?oauth_token=oauth_token" },
        body: "",
      });
    });
  });


  afterEach(() => {
    proxyDynamoDB.prototype.put.restore();
  });
});