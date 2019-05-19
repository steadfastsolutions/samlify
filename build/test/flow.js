"use strict";
var __assign = (this && this.__assign) || Object.assign || function(t) {
    for (var s, i = 1, n = arguments.length; i < n; i++) {
        s = arguments[i];
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
            t[p] = s[p];
    }
    return t;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var esaml2 = require("../index");
var fs_1 = require("fs");
var ava_1 = require("ava");
var _ = require("lodash");
var uuid = require("uuid");
var url = require("url");
var identityProvider = esaml2.IdentityProvider, serviceProvider = esaml2.ServiceProvider, idpMetadata = esaml2.IdPMetadata, spMetadata = esaml2.SPMetadata, utility = esaml2.Utility, libsaml = esaml2.SamlLib, ref = esaml2.Constants;
var getQueryParamByType = libsaml.getQueryParamByType;
var binding = ref.namespace.binding;
var algorithms = ref.algorithms;
var wording = ref.wording;
var signatureAlgorithms = algorithms.signature;
// Custom template
var loginResponseTemplate = {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: [
        { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
        { name: 'name', valueTag: 'user.name', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
    ],
};
var createTemplateCallback = function (idp, sp, user) { return function (template) {
    var _id = '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
    var now = new Date();
    var spEntityID = sp.entityMeta.getEntityID();
    var idpSetting = idp.entitySetting;
    var fiveMinutesLater = new Date(now.getTime());
    fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
    var tvalue = {
        ID: _id,
        AssertionID: idpSetting.generateID ? idpSetting.generateID() : "" + uuid.v4(),
        Destination: sp.entityMeta.getAssertionConsumerService(binding.post),
        Audience: spEntityID,
        SubjectRecipient: spEntityID,
        NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        NameID: user.email,
        Issuer: idp.entityMeta.getEntityID(),
        IssueInstant: now.toISOString(),
        ConditionsNotBefore: now.toISOString(),
        ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
        SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
        AssertionConsumerServiceURL: sp.entityMeta.getAssertionConsumerService(binding.post),
        EntityID: spEntityID,
        InResponseTo: '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        attrUserEmail: 'myemailassociatedwithsp@sp.com',
        attrUserName: 'mynameinsp',
    };
    return {
        id: _id,
        context: libsaml.replaceTagsByValue(template, tvalue),
    };
}; };
// Define of metadata
var _spKeyFolder = './test/key/sp/';
var _spPrivPem = String(fs_1.readFileSync(_spKeyFolder + 'privkey.pem'));
var _spPrivKey = _spKeyFolder + 'nocrypt.pem';
var _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';
var defaultIdpConfig = {
    privateKey: fs_1.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    isAssertionEncrypted: true,
    encPrivateKey: fs_1.readFileSync('./test/key/idp/encryptKey.pem'),
    encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
    metadata: fs_1.readFileSync('./test/misc/idpmeta.xml'),
};
var defaultSpConfig = {
    privateKey: fs_1.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    isAssertionEncrypted: true,
    encPrivateKey: fs_1.readFileSync('./test/key/sp/encryptKey.pem'),
    encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
    metadata: fs_1.readFileSync('./test/misc/spmeta.xml'),
};
// Define metadata
var IdPMetadata = idpMetadata(fs_1.readFileSync('./test/misc/idpmeta.xml'));
var SPMetadata = spMetadata(fs_1.readFileSync('./test/misc/spmeta.xml'));
var sampleSignedResponse = fs_1.readFileSync('./test/misc/response_signed.xml').toString();
var wrongResponse = fs_1.readFileSync('./test/misc/invalid_response.xml').toString();
var spCertKnownGood = fs_1.readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
var spPemKnownGood = fs_1.readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();
var noSignedIdpMetadata = fs_1.readFileSync('./test/misc/idpmeta_nosign.xml').toString().trim();
var spmetaNoAssertSign = fs_1.readFileSync('./test/misc/spmeta_noassertsign.xml').toString().trim();
var sampleRequestInfo = { extract: { authnrequest: { id: 'request_id' } } };
// Define entities
var idp = identityProvider(defaultIdpConfig);
var sp = serviceProvider(defaultSpConfig);
var idpNoEncrypt = identityProvider(__assign({}, defaultIdpConfig, { isAssertionEncrypted: false }));
var idpcustomNoEncrypt = identityProvider(__assign({}, defaultIdpConfig, { isAssertionEncrypted: false, loginResponseTemplate: loginResponseTemplate }));
var idpcustom = identityProvider(__assign({}, defaultIdpConfig, { loginResponseTemplate: loginResponseTemplate }));
var idpEncryptThenSign = identityProvider(__assign({}, defaultIdpConfig, { messageSigningOrder: 'encrypt-then-sign' }));
var spWantLogoutReqSign = serviceProvider(__assign({}, defaultSpConfig, { wantLogoutRequestSigned: true }));
var spWantLogoutResSign = serviceProvider(__assign({}, defaultSpConfig, { wantLogoutResponseSigned: true }));
var idpWantLogoutResSign = identityProvider(__assign({}, defaultIdpConfig, { wantLogoutResponseSigned: true }));
var spNoAssertSign = serviceProvider(__assign({}, defaultSpConfig, { metadata: spmetaNoAssertSign }));
var spNoAssertSignCustomConfig = serviceProvider(__assign({}, defaultSpConfig, { metadata: spmetaNoAssertSign, signatureConfig: {
        prefix: 'ds',
        location: { reference: '/samlp:Response/saml:Issuer', action: 'after' },
    } }));
function writer(str) {
    fs_1.writeFileSync('test.txt', str);
}
ava_1.default('create login request with redirect binding using default template and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, id, context, originalURL, SAMLRequest, Signature, SigAlg, octetString, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = sp.createLoginRequest(idp, 'redirect'), id = _a.id, context = _a.context;
                t.is(typeof id, 'string');
                t.is(typeof context, 'string');
                originalURL = url.parse(context, true);
                SAMLRequest = originalURL.query.SAMLRequest;
                Signature = originalURL.query.Signature;
                SigAlg = originalURL.query.SigAlg;
                delete originalURL.query.Signature;
                octetString = Object.keys(originalURL.query).map(function (q) { return q + '=' + encodeURIComponent(originalURL.query[q]); }).join('&');
                return [4 /*yield*/, idp.parseLoginRequest(sp, 'redirect', { query: { SAMLRequest: SAMLRequest, Signature: Signature, SigAlg: SigAlg }, octetString: octetString })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                t.is(extract.issuer, 'https://sp.example.org/metadata');
                t.is(typeof extract.authnrequest.id, 'string');
                t.is(extract.nameidpolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
                t.is(extract.nameidpolicy.allowcreate, 'false');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('create login request with post binding using default template and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, relayState, type, entityEndpoint, id, SAMLRequest, _b, samlContent, extract, sigAlg;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = sp.createLoginRequest(idp, 'post'), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, SAMLRequest = _a.context;
                t.is(typeof id, 'string');
                t.is(typeof SAMLRequest, 'string');
                t.is(typeof entityEndpoint, 'string');
                t.is(type, 'SAMLRequest');
                return [4 /*yield*/, idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest: SAMLRequest } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract, sigAlg = _b.sigAlg;
                t.is(extract.issuer, 'https://sp.example.org/metadata');
                t.is(typeof extract.authnrequest.id, 'string');
                t.is(extract.nameidpolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
                t.is(extract.nameidpolicy.allowcreate, 'false');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('signed in sp is not matched with the signed notation in idp with post request', function (t) {
    var _idp = identityProvider(__assign({}, defaultIdpConfig, { metadata: noSignedIdpMetadata }));
    try {
        var _a = sp.createLoginRequest(_idp, 'post'), id = _a.id, context = _a.context;
        t.fail();
    }
    catch (e) {
        t.is(e.message, 'metadata conflict - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
    }
});
ava_1.default('signed in sp is not matched with the signed notation in idp with redirect request', function (t) {
    var _idp = identityProvider(__assign({}, defaultIdpConfig, { metadata: noSignedIdpMetadata }));
    try {
        var _a = sp.createLoginRequest(_idp, 'redirect'), id = _a.id, context = _a.context;
        t.fail();
    }
    catch (e) {
        t.is(e.message, 'metadata conflict - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
    }
});
ava_1.default('create login request with redirect binding using [custom template]', function (t) {
    var _sp = serviceProvider(__assign({}, defaultSpConfig, { loginRequestTemplate: {
            context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
        } }));
    var _a = _sp.createLoginRequest(idp, 'redirect', function (template) {
        return {
            id: 'exposed_testing_id',
            context: template,
        };
    }), id = _a.id, context = _a.context;
    (id === 'exposed_testing_id' && _.isString(context)) ? t.pass() : t.fail();
});
ava_1.default('create login request with post binding using [custom template]', function (t) {
    var _sp = serviceProvider(__assign({}, defaultSpConfig, { loginRequestTemplate: {
            context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
        } }));
    var _a = _sp.createLoginRequest(idp, 'post', function (template) {
        return {
            id: 'exposed_testing_id',
            context: template,
        };
    }), id = _a.id, context = _a.context, entityEndpoint = _a.entityEndpoint, type = _a.type, relayState = _a.relayState;
    id === 'exposed_testing_id' &&
        _.isString(context) &&
        _.isString(relayState) &&
        _.isString(entityEndpoint) &&
        _.isEqual(type, 'SAMLRequest')
        ? t.pass() : t.fail();
});
ava_1.default('create login response with undefined binding', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, error;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, t.throws(idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, user)))];
            case 1:
                error = _a.sent();
                t.is(error.message, 'this binding is not supported');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('create post login response', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, context;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user))];
            case 1:
                _a = _b.sent(), id = _a.id, context = _a.context;
                _.isString(id) && _.isString(context) ? t.pass() : t.fail();
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('create logout request with redirect binding', function (t) {
    var _a = sp.createLogoutRequest(idp, 'redirect', { email: 'user@esaml2' }), id = _a.id, context = _a.context;
    _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});
ava_1.default('create logout request with post binding', function (t) {
    var _a = sp.createLogoutRequest(idp, 'post', { email: 'user@esaml2' }), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, context = _a.context;
    _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLRequest') ? t.pass() : t.fail();
});
ava_1.default('create logout response with undefined binding', function (t) {
    try {
        var _a = idp.createLogoutResponse(sp, {}, 'undefined', '', createTemplateCallback(idp, sp, {})), id = _a.id, context = _a.context;
        t.fail();
    }
    catch (e) {
        t.is(e.message, 'this binding is not supported');
    }
});
ava_1.default('create logout response with redirect binding', function (t) {
    var _a = idp.createLogoutResponse(sp, {}, 'redirect', '', createTemplateCallback(idp, sp, {})), id = _a.id, context = _a.context;
    _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});
ava_1.default('create logout response with post binding', function (t) {
    var _a = idp.createLogoutResponse(sp, {}, 'post', '', createTemplateCallback(idp, sp, {})), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, context = _a.context;
    _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLResponse') ? t.pass() : t.fail();
});
// Check if the response data parsing is correct
// All test cases are using customize template
// simulate idp-initiated sso
ava_1.default('send response with signed assertion and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send response with [custom template] signed assertion and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var requestInfo, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpcustomNoEncrypt.createLoginResponse(sp, requestInfo, 'post', user, 
                    // declare the callback to do custom template replacement
                    createTemplateCallback(idpcustomNoEncrypt, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, sp.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                // test phrase 3: check if attribute is parsed properly
                t.is(extract.attribute.name, 'mynameinsp');
                t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send response with signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpNoEncrypt.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spNoAssertSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send response with [custom template] and signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var requestInfo, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpcustomNoEncrypt.createLoginResponse(spNoAssertSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' }, createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                // test phrase 3: check if attribute is parsed properly
                t.is(extract.attribute.name, 'mynameinsp');
                t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with signed assertion + signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var spWantMessageSign, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                spWantMessageSign = serviceProvider(__assign({}, defaultSpConfig, { wantMessageSigned: true }));
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpNoEncrypt.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spWantMessageSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spWantMessageSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'object');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with [custom template] and signed assertion + signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var spWantMessageSign, requestInfo, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                spWantMessageSign = serviceProvider(__assign({}, defaultSpConfig, { wantMessageSigned: true }));
                requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpcustomNoEncrypt.createLoginResponse(spWantMessageSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' }, createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'object');
                // test phrase 3: check if attribute is parsed properly
                t.is(extract.attribute.name, 'mynameinsp');
                t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with encrypted non-signed assertion and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idp.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spNoAssertSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spNoAssertSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with encrypted signed assertion and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with [custom template] and encrypted signed assertion and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var requestInfo, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpcustom.createLoginResponse(sp, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' }, createTemplateCallback(idpcustom, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, sp.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                // test phrase 3: check if attribute is parsed properly
                t.is(extract.attribute.name, 'mynameinsp');
                t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with encrypted signed assertion + signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var spWantMessageSign, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                spWantMessageSign = serviceProvider(__assign({}, defaultSpConfig, { wantMessageSigned: true }));
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idp.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spWantMessageSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spWantMessageSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'object');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with [custom template] encrypted signed assertion + signed message and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var spWantMessageSign, requestInfo, user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                spWantMessageSign = serviceProvider(__assign({}, defaultSpConfig, { wantMessageSigned: true }));
                requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpcustom.createLoginResponse(spWantMessageSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' }, createTemplateCallback(idpcustom, spWantMessageSign, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spWantMessageSign.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                // test phrase 1: samlContent is a string (parsed version)
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                // test phrase 2: useful information is included in extract object
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'object');
                // test phrase 3: check if attribute is parsed properly
                t.is(extract.attribute.name, 'mynameinsp');
                t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
                return [2 /*return*/];
        }
    });
}); });
// simulate idp-init slo
ava_1.default('idp sends a redirect logout request without signature and sp parses it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, id, context, query, originalURL, SAMLRequest, _b, samlContent, extract, sigAlg;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'user@esaml2.com' }), id = _a.id, context = _a.context;
                query = url.parse(context).query;
                t.is(_.includes(query, 'SAMLRequest='), true);
                t.is(typeof id, 'string');
                t.is(typeof context, 'string');
                originalURL = url.parse(context, true);
                SAMLRequest = encodeURIComponent(originalURL.query.SAMLRequest);
                return [4 /*yield*/, sp.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest: SAMLRequest } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract, sigAlg = _b.sigAlg;
                t.is(sigAlg, undefined);
                t.is(typeof samlContent, 'string');
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(extract.signature, undefined);
                t.is(typeof extract.logoutrequest.id, 'string');
                t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
                t.is(extract.issuer, 'https://idp.example.com/metadata');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('idp sends a redirect logout request with signature and sp parses it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, id, context, query, originalURL, SAMLRequest, Signature, SigAlg, octetString, _b, samlContent, extract, sigAlg;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = idp.createLogoutRequest(spWantLogoutReqSign, 'redirect', { logoutNameID: 'user@esaml2.com' }), id = _a.id, context = _a.context;
                query = url.parse(context).query;
                t.is(_.includes(query, 'SAMLRequest='), true);
                t.is(_.includes(query, 'SigAlg='), true);
                t.is(_.includes(query, 'Signature='), true);
                t.is(typeof id, 'string');
                t.is(typeof context, 'string');
                originalURL = url.parse(context, true);
                SAMLRequest = originalURL.query.SAMLRequest;
                Signature = originalURL.query.Signature;
                SigAlg = originalURL.query.SigAlg;
                delete originalURL.query.Signature;
                octetString = Object.keys(originalURL.query).map(function (q) { return q + '=' + encodeURIComponent(originalURL.query[q]); }).join('&');
                return [4 /*yield*/, spWantLogoutReqSign.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest: SAMLRequest, Signature: Signature, SigAlg: SigAlg }, octetString: octetString })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract, sigAlg = _b.sigAlg;
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(extract.issuer, 'https://idp.example.com/metadata');
                t.is(typeof extract.logoutrequest.id, 'string');
                t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
                t.is(extract.signature, undefined); // redirect binding doesn't embed the signature
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('idp sends a post logout request without signature and sp parses it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, relayState, type, entityEndpoint, id, context, _b, samlContent, extract, sigAlg;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'user@esaml2.com' }), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, context = _a.context;
                t.is(typeof id, 'string');
                t.is(typeof context, 'string');
                t.is(typeof entityEndpoint, 'string');
                t.is(type, 'SAMLRequest');
                return [4 /*yield*/, sp.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract, sigAlg = _b.sigAlg;
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(extract.issuer, 'https://idp.example.com/metadata');
                t.is(typeof extract.logoutrequest.id, 'string');
                t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
                t.is(extract.signature, undefined);
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('idp sends a post logout request with signature and sp parses it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, relayState, type, entityEndpoint, id, context, _b, samlContent, extract, sigAlg;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { logoutNameID: 'user@esaml2.com' }), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, context = _a.context;
                t.is(typeof id, 'string');
                t.is(typeof context, 'string');
                t.is(typeof entityEndpoint, 'string');
                t.is(type, 'SAMLRequest');
                return [4 /*yield*/, spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract, sigAlg = _b.sigAlg;
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(extract.issuer, 'https://idp.example.com/metadata');
                t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
                t.is(typeof extract.logoutrequest.id, 'string');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
// simulate init-slo
ava_1.default('sp sends a post logout response without signature and parse', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, relayState, type, entityEndpoint, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = sp.createLogoutResponse(idp, null, 'post', '', createTemplateCallback(idp, sp, {})), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, idp.parseLogoutResponse(sp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                t.is(extract.signature, undefined);
                t.is(extract.issuer, 'https://sp.example.org/metadata');
                t.is(typeof extract.logoutresponse.id, 'string');
                t.is(extract.logoutresponse.destination, 'https://idp.example.org/sso/SingleLogoutService');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('sp sends a post logout response with signature and parse', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var _a, relayState, type, entityEndpoint, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _a = sp.createLogoutResponse(idpWantLogoutResSign, null, 'post', '', createTemplateCallback(idpWantLogoutResSign, sp, {})), relayState = _a.relayState, type = _a.type, entityEndpoint = _a.entityEndpoint, id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, idpWantLogoutResSign.parseLogoutResponse(sp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 1:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                t.is(typeof extract.signature, 'string');
                t.is(extract.issuer, 'https://sp.example.org/metadata');
                t.is(typeof extract.logoutresponse.id, 'string');
                t.is(extract.logoutresponse.destination, 'https://idp.example.org/sso/SingleLogoutService');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'user@esaml2.com' };
                return [4 /*yield*/, idpEncryptThenSign.createLoginResponse(spNoAssertSignCustomConfig, sampleRequestInfo, 'post', user, createTemplateCallback(idpEncryptThenSign, spNoAssertSignCustomConfig, user), true)];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                return [4 /*yield*/, spNoAssertSignCustomConfig.parseLoginResponse(idpEncryptThenSign, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                t.is(typeof id, 'string');
                t.is(samlContent.startsWith('<samlp:Response'), true);
                t.is(samlContent.endsWith('/samlp:Response>'), true);
                t.is(extract.nameid, 'user@esaml2.com');
                t.is(typeof extract.signature, 'string');
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('Customize prefix (saml2) for encrypted assertion tag', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, idpCustomizePfx, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'test@email.com' };
                idpCustomizePfx = identityProvider(Object.assign(defaultIdpConfig, { tagPrefix: {
                        encryptedAssertion: 'saml2',
                    } }));
                return [4 /*yield*/, idpCustomizePfx.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpCustomizePfx, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                t.is(utility.base64Decode(SAMLResponse).includes('saml2:EncryptedAssertion'), true);
                return [4 /*yield*/, sp.parseLoginResponse(idpCustomizePfx, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('Customize prefix (default is saml) for encrypted assertion tag', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, _b, samlContent, extract;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                user = { email: 'test@email.com' };
                return [4 /*yield*/, idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user))];
            case 1:
                _a = _c.sent(), id = _a.id, SAMLResponse = _a.context;
                t.is(utility.base64Decode(SAMLResponse).includes('saml:EncryptedAssertion'), true);
                return [4 /*yield*/, sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse: SAMLResponse } })];
            case 2:
                _b = _c.sent(), samlContent = _b.samlContent, extract = _b.extract;
                return [2 /*return*/];
        }
    });
}); });
ava_1.default('avoid mitm attack', function (t) { return __awaiter(_this, void 0, void 0, function () {
    var user, _a, id, SAMLResponse, rawResponse, attackResponse, error;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                user = { email: 'user@email.com' };
                return [4 /*yield*/, idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user))];
            case 1:
                _a = _b.sent(), id = _a.id, SAMLResponse = _a.context;
                rawResponse = String(utility.base64Decode(SAMLResponse, true));
                attackResponse = "<NameID>evil@evil.com" + rawResponse + "</NameID>";
                return [4 /*yield*/, t.throws(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(attackResponse) } }))];
            case 2:
                error = _b.sent();
                return [2 /*return*/];
        }
    });
}); });
//# sourceMappingURL=flow.js.map