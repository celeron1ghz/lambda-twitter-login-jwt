'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

describe('/callback test', () => {
  const callback = (error, result) => new Promise((resolve, reject) => {
    error ? reject(error) : resolve(result)
  });

  let lambda;
  let proxyDynamoDB;
  let proxyOAuth;
  let proxySSM;

  beforeEach(() => {
    proxySSM = class { getParameter () {} };
    proxyOAuth = class { createInstance(){}  getOAuthAccessToken(){} };
    proxyDynamoDB = class { put(){}  get(){} };

    lambda = proxyquire('./handler', {
      'aws-sdk': { DynamoDB: { DocumentClient: proxyDynamoDB }, SSM: proxySSM },
      "./lib/TwitterOAuth":  proxyOAuth,
    });
  });


  it('errors on no cookie', () => {
    return expect(lambda.callback({ headers: {} }, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 400,
        body: JSON.stringify({ error: "NO_DATA" }),
      });
    });
  });


  it('errors on no data', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get').returns({  promise: () => Promise.resolve({ Item: null })  });

    return expect(lambda.callback({ headers: { Cookie: "mogemoge" } }, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 401,
        body: JSON.stringify({ error: "NO_DATA" }),
      });
    });
  });


  it('errors on unknown reason', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get').returns({  promise: () => Promise.reject(new Error("popopopopopo"))  });
    sinon.stub(proxyOAuth, 'createInstance').returns(
      Promise.resolve({
        getOAuthAccessToken: () =>
          Promise.resolve({ oauth_token: "oauth_token", oauth_token_secret: "oauth_sec", results: {} }),
        call_get_api: () =>
          Promise.resolve(112233),
      })
    );

    sinon.stub(proxySSM.prototype, 'getParameter').returns(
      { promise: () => Promise.resolve({ Parameter: { Value: "mogemoge" } })  }
    );

    sinon.stub(proxyDynamoDB.prototype, 'put').returns({  promise: () => Promise.resolve(null)  });

    return expect(lambda.callback({ headers: { Cookie: "mogemoge" }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "popopopopopo" }),
      });
    });
  });


  it('ok', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get').returns({  promise: () => Promise.resolve({ Item: { session: "fugafuga" } })  });
    sinon.stub(proxyOAuth, 'createInstance').returns(
      Promise.resolve({
        getOAuthAccessToken: () =>
          Promise.resolve({ oauth_token: "oauth_token", oauth_token_secret: "oauth_sec", results: {} }),
        call_get_api: () =>
          Promise.resolve(112233),
      })
    );

    sinon.stub(proxySSM.prototype, 'getParameter').returns(
      { promise: () => Promise.resolve({ Parameter: { Value: "mogemoge" } })  }
    );

    sinon.stub(proxyDynamoDB.prototype, 'put').returns({  promise: () => Promise.resolve(null)  });

    return expect(
      lambda.callback({ headers: { Cookie: "mogemoge" }, queryStringParameters: {}}, {}, callback)
    ).to.be.fulfilled.then(result => {
      const body = result.body;
      delete result.body;

      expect(body).to.match(/^<script>window.opener.postMessage\("[\w\-_]+\.[\w\-_]+\.[\w\-_]+", "\*"\); window.close\(\);<\/script>/);

      expect(result).to.deep.equal({ statusCode: 200, headers: { "Content-Type": "text/html" } });
    });
  });


  afterEach(() => {
    //proxyDynamoDB.prototype.put.restore();
  });
});