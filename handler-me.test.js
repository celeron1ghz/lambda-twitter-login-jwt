'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

const jwt = require("jsonwebtoken");

describe('/me test', () => {
  const callback = (error, result) => new Promise((resolve, reject) => {
    error ? reject(error) : resolve(result)
  });

  let lambda;
  let proxyDynamoDB;
  let proxySSM;

  beforeEach(() => {
    proxyDynamoDB = class { get () {} };
    proxySSM     = class { getParameter () {} };

    lambda = proxyquire('./handler', {
      'aws-sdk': {
        DynamoDB: { DocumentClient: proxyDynamoDB },
        SSM: proxySSM,
      },
    });
  });


  it('errors on not specify authorization header', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get').returns({  promise: () => Promise.resolve({ Item: null })  });

    return expect(lambda.me({ headers: {}}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "INVALID_HEADER1" }),
      });
    });
  });


  it('errors on invalid authorization header', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get'    ).returns({  promise: () => Promise.resolve({ Item: null })  });
    sinon.stub(proxySSM.prototype, 'getParameter').returns({  promise: () => Promise.resolve({ Parameter: { Value: 1 } })  });

    return expect(lambda.me({ headers: { Authorization: "piyopiyo" }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "INVALID_HEADER2" }),
      });
    });
  });


  it('errors on invalid jwt token', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get'    ).returns({  promise: () => Promise.resolve({ Item: null })  });
    sinon.stub(proxySSM.prototype, 'getParameter').returns({  promise: () => Promise.resolve({ Parameter: { Value: 1 } })  });

    return expect(lambda.me({ headers: { Authorization: "Bearer a.a.a" }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "INVALID_HEADER3" }),
      });
    });
  });


  it('errors on no data', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get'    ).returns({  promise: () => Promise.resolve({ Item: null })  });
    sinon.stub(proxySSM.prototype, 'getParameter').returns({  promise: () => Promise.resolve({ Parameter: { Value: "1" } })  });

    const signed = jwt.sign(JSON.stringify({ sessid: 'mogemogefugafuga' }), "1");

    return expect(lambda.me({ headers: { Authorization: "Bearer " + signed }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "DATA_NOT_EXIST1" }),
      });
    });
  });


  it('errors on no data of login', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get'    ).returns({  promise: () => Promise.resolve({ Item: {} })  });
    sinon.stub(proxySSM.prototype, 'getParameter').returns({  promise: () => Promise.resolve({ Parameter: { Value: "1" } })  });

    const signed = jwt.sign(JSON.stringify({ sessid: 'mogemogefugafuga' }), "1");

    return expect(lambda.me({ headers: { Authorization: "Bearer " + signed }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "DATA_NOT_EXIST2" }),
      });
    });
  });


  it('ok', () => {
    sinon.stub(proxyDynamoDB.prototype, 'get'    ).returns({  promise: () => Promise.resolve({ Item: {twitter_id: 'mogemoge'  } })  });
    sinon.stub(proxySSM.prototype, 'getParameter').returns({  promise: () => Promise.resolve({ Parameter: { Value: "1" } })  });

    const signed = jwt.sign(JSON.stringify({ sessid: 'mogemogefugafuga' }), "1");

    return expect(lambda.me({ headers: { Authorization: "Bearer " + signed }}, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 200,
        headers: {
          "Access-Control-Allow-Credentials": true,
          "Access-Control-Allow-Origin": undefined,
        },
        body: JSON.stringify({ twitter_id: "mogemoge" }),
      });
    });
  });


  afterEach(() => {
    proxyDynamoDB.prototype.get.restore();
  });
});