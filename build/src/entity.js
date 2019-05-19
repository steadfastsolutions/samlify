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
Object.defineProperty(exports, "__esModule", { value: true });
/**
* @file entity.ts
* @author tngan
* @desc  An abstraction for identity provider and service provider.
*/
var utility_1 = require("./utility");
var urn_1 = require("./urn");
var uuid = require("uuid");
var libsaml_1 = require("./libsaml");
var metadata_idp_1 = require("./metadata-idp");
var metadata_sp_1 = require("./metadata-sp");
var binding_redirect_1 = require("./binding-redirect");
var binding_post_1 = require("./binding-post");
var lodash_1 = require("lodash");
var dataEncryptionAlgorithm = urn_1.algorithms.encryption.data;
var keyEncryptionAlgorithm = urn_1.algorithms.encryption.key;
var bindDict = urn_1.wording.binding;
var signatureAlgorithms = urn_1.algorithms.signature;
var messageSigningOrders = urn_1.messageConfigurations.signingOrder;
var nsBinding = urn_1.namespace.binding;
var defaultEntitySetting = {
    wantLogoutResponseSigned: false,
    messageSigningOrder: messageSigningOrders.SIGN_THEN_ENCRYPT,
    wantLogoutRequestSigned: false,
    allowCreate: false,
    isAssertionEncrypted: false,
    requestSignatureAlgorithm: signatureAlgorithms.RSA_SHA256,
    dataEncryptionAlgorithm: dataEncryptionAlgorithm.AES_256,
    keyEncryptionAlgorithm: keyEncryptionAlgorithm.RSA_1_5,
    generateID: function () { return ('_' + uuid.v4()); },
    relayState: '',
};
var Entity = /** @class */ (function () {
    /**
    * @param entitySetting
    * @param entityMeta is the entity metadata, deprecated after 2.0
    */
    function Entity(entitySetting, entityType) {
        this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
        var metadata = entitySetting.metadata || entitySetting;
        switch (entityType) {
            case 'idp':
                this.entityMeta = metadata_idp_1.default(metadata);
                this.entitySetting.wantAuthnRequestsSigned = this.entityMeta.isWantAuthnRequestsSigned();
                break;
            case 'sp':
                this.entityMeta = metadata_sp_1.default(metadata);
                this.entitySetting.authnRequestsSigned = this.entityMeta.isAuthnRequestSigned();
                this.entitySetting.wantAssertionsSigned = this.entityMeta.isWantAssertionsSigned();
                break;
            default:
                throw new Error('undefined entity type');
        }
    }
    /**
    * @desc  Returns the setting of entity
    * @return {object}
    */
    Entity.prototype.getEntitySetting = function () {
        return this.entitySetting;
    };
    /**
    * @desc  Returns the xml string of entity metadata
    * @return {string}
    */
    Entity.prototype.getMetadata = function () {
        return this.entityMeta.getMetadata();
    };
    /**
    * @desc  Exports the entity metadata into specified folder
    * @param  {string} exportFile indicates the file name
    */
    Entity.prototype.exportMetadata = function (exportFile) {
        return this.entityMeta.exportMetadata(exportFile);
    };
    /** * @desc  Verify fields with the one specified in metadata
    * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
    * @param  {string} metaField is a string indicating the same field specified in metadata
    * @return {boolean} True/False
    */
    Entity.prototype.verifyFields = function (field, metaField) {
        if (lodash_1.isString(field)) {
            return field === metaField;
        }
        if (utility_1.isNonEmptyArray(field)) {
            var res_1 = true;
            field.forEach(function (f) {
                if (f !== metaField) {
                    res_1 = false;
                    return;
                }
            });
            return res_1;
        }
        return false;
    };
    /**
    * @desc  Verify time stamp
    * @param  {date} notBefore
    * @param  {date} notOnOrAfter
    * @return {boolean}
    */
    Entity.prototype.verifyTime = function (notBefore, notOnOrAfter) {
        var now = new Date();
        if (lodash_1.isUndefined(notBefore) && lodash_1.isUndefined(notOnOrAfter)) {
            return true; // throw exception todo
        }
        if (!lodash_1.isUndefined(notBefore) && lodash_1.isUndefined(notOnOrAfter)) {
            return +notBefore <= +now;
        }
        if (lodash_1.isUndefined(notBefore) && !lodash_1.isUndefined(notOnOrAfter)) {
            return now < notOnOrAfter;
        }
        return +notBefore <= +now && now < notOnOrAfter;
    };
    /**
    * @desc  Validate and parse the request/response with different bindings
    * @param  {object} opts is the options for abstraction
    * @param  {string} binding is the protocol bindings (e.g. redirect, post)
    * @param  {request} req is the http request
    * @param  {Metadata} targetEntityMetadata either IDP metadata or SP metadata
    * @return {ParseResult} parseResult
    */
    Entity.prototype.genericParser = function (opts, binding, req) {
        return __awaiter(this, void 0, void 0, function () {
            var query, body, octetString, here, entityMeta, options, parseResult, supportBindings, fields, parserType, type, from, _a, checkSignature, _b, decryptAssertion, targetEntityMetadata, assertionConsumerService, singleSignOnService, singleLogoutServices, reqQuery, samlContent, xmlString, sigAlg, signature, encodedRequest, res, issuer;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        query = req.query, body = req.body, octetString = req.octetString;
                        here = this;
                        entityMeta = this.entityMeta;
                        options = opts || {};
                        supportBindings = [nsBinding.redirect, nsBinding.post];
                        fields = options.parserFormat, parserType = options.parserType, type = options.type, from = options.from, _a = options.checkSignature, checkSignature = _a === void 0 ? true : _a, _b = options.decryptAssertion, decryptAssertion = _b === void 0 ? false : _b;
                        targetEntityMetadata = opts.from.entityMeta;
                        if (type === 'login') {
                            if (entityMeta.getAssertionConsumerService) {
                                assertionConsumerService = entityMeta.getAssertionConsumerService(binding);
                                if (!assertionConsumerService) {
                                    supportBindings = [];
                                }
                            }
                            else if (entityMeta.getSingleSignOnService) {
                                singleSignOnService = entityMeta.getSingleSignOnService(binding);
                                if (!singleSignOnService) {
                                    supportBindings = [];
                                }
                            }
                        }
                        else if (type === 'logout') {
                            singleLogoutServices = entityMeta.getSingleLogoutService(binding);
                            if (!singleLogoutServices) {
                                supportBindings = [];
                            }
                        }
                        else {
                            throw new Error('Invalid type in genericParser');
                        }
                        if (!(binding === bindDict.redirect && supportBindings.indexOf(nsBinding[binding]) !== -1)) return [3 /*break*/, 3];
                        reqQuery = query;
                        samlContent = reqQuery[libsaml_1.default.getQueryParamByType(parserType)];
                        if (samlContent === undefined) {
                            throw new Error('bad request');
                        }
                        xmlString = utility_1.inflateString(decodeURIComponent(samlContent));
                        if (!(parserType === 'SAMLResponse')) return [3 /*break*/, 2];
                        return [4 /*yield*/, libsaml_1.default.isValidXml(xmlString)];
                    case 1:
                        _c.sent();
                        _c.label = 2;
                    case 2:
                        if (checkSignature) {
                            sigAlg = reqQuery.SigAlg, signature = reqQuery.Signature;
                            if (signature && sigAlg) {
                                if (libsaml_1.default.verifyMessageSignature(targetEntityMetadata, octetString, new Buffer(decodeURIComponent(signature), 'base64'), sigAlg)) {
                                    parseResult = {
                                        samlContent: xmlString,
                                        sigAlg: decodeURIComponent(sigAlg),
                                        extract: libsaml_1.default.extractor(xmlString, fields),
                                    };
                                }
                                else {
                                    // Fail to verify message signature
                                    throw new Error('fail to verify message signature in request');
                                }
                            }
                            else {
                                // Missing signature or signature algorithm
                                throw new Error('missing signature or signature algorithm');
                            }
                        }
                        else {
                            parseResult = {
                                samlContent: xmlString,
                                extract: libsaml_1.default.extractor(xmlString, fields),
                            };
                        }
                        return [2 /*return*/, parseResult];
                    case 3:
                        if (!(binding === bindDict.post && supportBindings.indexOf(nsBinding[binding]) !== -1)) return [3 /*break*/, 8];
                        encodedRequest = body[libsaml_1.default.getQueryParamByType(parserType)];
                        res = String(utility_1.base64Decode(encodedRequest));
                        issuer = targetEntityMetadata.getEntityID();
                        //verify signature before decryption if IDP encrypted then signed the message
                        if (checkSignature && from.entitySetting.messageSigningOrder === messageSigningOrders.ENCRYPT_THEN_SIGN) {
                            // verify the signatures (for both assertion/message)
                            if (!libsaml_1.default.verifySignature(res, {
                                cert: opts.from.entityMeta,
                                signatureAlgorithm: opts.from.entitySetting.requestSignatureAlgorithm,
                            })) {
                                throw new Error('incorrect signature');
                            }
                        }
                        if (!(parserType === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted)) return [3 /*break*/, 5];
                        return [4 /*yield*/, libsaml_1.default.decryptAssertion(here, res)];
                    case 4:
                        res = _c.sent();
                        _c.label = 5;
                    case 5:
                        if (!(parserType === 'SAMLResponse')) return [3 /*break*/, 7];
                        return [4 /*yield*/, libsaml_1.default.isValidXml(res)];
                    case 6:
                        _c.sent();
                        _c.label = 7;
                    case 7:
                        parseResult = {
                            samlContent: res,
                            extract: libsaml_1.default.extractor(res, fields),
                        };
                        if (checkSignature && from.entitySetting.messageSigningOrder === messageSigningOrders.SIGN_THEN_ENCRYPT) {
                            // verify the signatures (for both assertion/message)
                            if (!libsaml_1.default.verifySignature(res, {
                                cert: opts.from.entityMeta,
                                signatureAlgorithm: opts.from.entitySetting.requestSignatureAlgorithm,
                            })) {
                                throw new Error('incorrect signature');
                            }
                        }
                        if (!here.verifyFields(parseResult.extract.issuer, issuer)) {
                            throw new Error('incorrect issuer');
                        }
                        return [2 /*return*/, parseResult];
                    case 8: 
                    // Will support artifact in the next release
                    throw new Error('this binding is not supported');
                }
            });
        });
    };
    /** @desc   Generates the logout request for developers to design their own method
    * @param  {ServiceProvider} sp     object of service provider
    * @param  {string}   binding       protocol binding
    * @param  {object}   user          current logged user (e.g. user)
    * @param  {string} relayState      the URL to which to redirect the user when logout is complete
    * @param  {function} customTagReplacement     used when developers have their own login response template
    */
    Entity.prototype.createLogoutRequest = function (targetEntity, binding, user, relayState, customTagReplacement) {
        if (relayState === void 0) { relayState = ''; }
        if (binding === urn_1.wording.binding.redirect) {
            return binding_redirect_1.default.logoutRequestRedirectURL(user, {
                init: this,
                target: targetEntity,
            }, relayState, customTagReplacement);
        }
        if (binding === urn_1.wording.binding.post) {
            var entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding);
            var context = binding_post_1.default.base64LogoutRequest(user, libsaml_1.default.createXPath('Issuer'), { init: this, target: targetEntity }, customTagReplacement);
            return __assign({}, context, { relayState: relayState,
                entityEndpoint: entityEndpoint, type: 'SAMLRequest' });
        }
        // Will support artifact in the next release
        throw new Error('The binding is not support');
    };
    /**
    * @desc  Generates the logout response for developers to design their own method
    * @param  {IdentityProvider} idp               object of identity provider
    * @param  {object} requestInfo                 corresponding request, used to obtain the id
    * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
    * @param  {string} binding                     protocol binding
    * @param  {function} customTagReplacement                 used when developers have their own login response template
    */
    Entity.prototype.createLogoutResponse = function (target, requestInfo, binding, relayState, customTagReplacement) {
        if (relayState === void 0) { relayState = ''; }
        var protocol = urn_1.namespace.binding[binding];
        if (protocol === urn_1.namespace.binding.redirect) {
            return binding_redirect_1.default.logoutResponseRedirectURL(requestInfo, {
                init: this,
                target: target,
            }, relayState, customTagReplacement);
        }
        if (protocol === urn_1.namespace.binding.post) {
            var context = binding_post_1.default.base64LogoutResponse(requestInfo, {
                init: this,
                target: target,
            }, customTagReplacement);
            return __assign({}, context, { relayState: relayState, entityEndpoint: target.entityMeta.getSingleLogoutService(binding), type: 'SAMLResponse' });
        }
        throw new Error('this binding is not supported');
    };
    /**
    * @desc   Validation of the parsed the URL parameters
    * @param  {IdentityProvider}   idp             object of identity provider
    * @param  {string}   binding                   protocol binding
    * @param  {request}   req                      request
    * @return {Promise}
    */
    Entity.prototype.parseLogoutRequest = function (from, binding, req) {
        var checkSignature = this.entitySetting.wantLogoutRequestSigned;
        var parserType = 'LogoutRequest';
        var type = 'logout';
        return this.genericParser({
            from: from,
            type: type,
            parserType: parserType,
            checkSignature: checkSignature,
            parserFormat: [
                'NameID',
                'Issuer',
                { localName: 'Signature', extractEntireBody: true },
                { localName: 'LogoutRequest', attributes: ['ID', 'Destination'] },
            ],
        }, binding, req);
    };
    /**
    * @desc   Validation of the parsed the URL parameters
    * @param  {object} config                      config for the parser
    * @param  {string}   binding                   protocol binding
    * @param  {request}   req                      request
    * @return {Promise}
    */
    Entity.prototype.parseLogoutResponse = function (from, binding, req) {
        var checkSignature = this.entitySetting.wantLogoutResponseSigned;
        var supportBindings = ['post'];
        var parserType = 'LogoutResponse';
        var type = 'logout';
        return this.genericParser({
            from: from,
            type: type,
            parserType: parserType,
            checkSignature: checkSignature,
            supportBindings: supportBindings,
            parserFormat: [
                { localName: 'StatusCode', attributes: ['Value'] },
                'Issuer',
                { localName: 'Signature', extractEntireBody: true },
                { localName: 'LogoutResponse', attributes: ['ID', 'Destination', 'InResponseTo'] },
            ],
        }, binding, req);
    };
    return Entity;
}());
exports.default = Entity;
//# sourceMappingURL=entity.js.map