"use strict";
/**
* @file SamlLib.js
* @author tngan
* @desc  A simple library including some common functions
*/
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
var xmldom_1 = require("xmldom");
var utility_1 = require("./utility");
var urn_1 = require("./urn");
var xpath_1 = require("xpath");
var camel = require("camelcase");
var lodash_1 = require("lodash");
var nrsa = require("node-rsa");
var xml_crypto_1 = require("xml-crypto");
var xmlenc = require("xml-encryption");
var xsd = require("libxml-xsd");
var path = require("path");
var signatureAlgorithms = urn_1.algorithms.signature;
var digestAlgorithms = urn_1.algorithms.digest;
var certUse = urn_1.wording.certUse;
var requestTags = urn_1.tags.request;
var urlParams = urn_1.wording.urlParams;
var dom = xmldom_1.DOMParser;
var libSaml = function () {
    /**
    * @desc helper function to get back the query param for redirect binding for SLO/SSO
    * @type {string}
    */
    function getQueryParamByType(type) {
        if ([urlParams.logoutRequest, urlParams.samlRequest].indexOf(type) !== -1) {
            return urlParams.samlRequest;
        }
        if ([urlParams.logoutResponse, urlParams.samlResponse].indexOf(type) !== -1) {
            return urlParams.samlResponse;
        }
        throw new Error('undefined parserType');
    }
    /**
     *
     */
    var nrsaAliasMapping = {
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'sha512',
    };
    /**
    * @desc Default login request template
    * @type {LoginRequestTemplate}
    */
    var defaultLoginRequestTemplate = {
        context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer></samlp:AuthnRequest>',
    };
    /**
    * @desc Default logout request template
    * @type {LogoutRequestTemplate}
    */
    var defaultLogoutRequestTemplate = {
        context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID SPNameQualifier="{EntityID}" Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
    };
    /**
    * @desc Default login response template
    * @type {LoginResponseTemplate}
    */
    var defaultLoginResponseTemplate = {
        context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
        attributes: [],
    };
    /**
    * @desc Default logout response template
    * @type {LogoutResponseTemplate}
    */
    var defaultLogoutResponseTemplate = {
        context: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
    };
    /**
    * @private
    * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
    * @param {string} sigAlg    signature algorithm
    * @return {string/null} signing algorithm short-hand for the module node-rsa
    */
    function getSigningScheme(sigAlg) {
        var algAlias = nrsaAliasMapping[sigAlg];
        if (!lodash_1.isUndefined(algAlias)) {
            return algAlias;
        }
        return nrsaAliasMapping[signatureAlgorithms.RSA_SHA1]; // default value
    }
    /**
    * @private
    * @desc Get the digest algorithms by signature algorithms
    * @param {string} sigAlg    signature algorithm
    * @return {string/null} digest algorithm
    */
    function getDigestMethod(sigAlg) {
        var digestAlg = digestAlgorithms[sigAlg];
        if (!lodash_1.isUndefined(digestAlg)) {
            return digestAlg;
        }
        return null; // default value
    }
    /**
    * @private
    * @desc Helper function used by another private function: getAttributes
    * @param  {xml} xmlDoc          used xml document
    * @param  {string} localName    tag name without prefix
    * @param  {string} attribute    name of attribute
    * @return {string} attribute value
    */
    function getAttribute(xmlDoc, localName, attribute) {
        var xpathStr = createXPath({
            name: localName,
            attr: attribute,
        });
        var selection = xpath_1.select(xpathStr, xmlDoc);
        if (selection.length !== 1) {
            return undefined;
        }
        else {
            return selection[0].nodeValue.toString();
        }
    }
    /**
    * @private
    * @desc Get the attibutes
    * @param  {xml} xmlDoc              used xml document
    * @param  {string} localName        tag name without prefix
    * @param  {[string]} attributes     array consists of name of attributes
    * @return {string/array}
    */
    function getAttributes(xmlDoc, localName, attributes) {
        var xpathStr = createXPath(localName);
        var selection = xpath_1.select(xpathStr, xmlDoc);
        var data = [];
        if (selection.length === 0) {
            return undefined;
        }
        selection.forEach(function (s) {
            var dat = {};
            var doc = new dom().parseFromString(String(s));
            attributes.forEach(function (attr) {
                dat[attr.toLowerCase()] = getAttribute(doc, localName, attr);
            });
            data.push(dat);
        });
        return data.length === 1 ? data[0] : data;
    }
    /**
    * @private
    * @desc Helper function used to return result with complex format
    * @param  {xml} xmlDoc              used xml document
    * @param  {string} localName        tag name without prefix
    * @param  {string} localNameKey     key associated with tag name
    * @param  {string} valueTag         tag of the value
    */
    function getInnerTextWithOuterKey(xmlDoc, localName, localNameKey, valueTag) {
        var xpathStr = createXPath(localName);
        var selection = xpath_1.select(xpathStr, xmlDoc);
        var obj = {};
        selection.forEach(function (_s) {
            var xd = new dom().parseFromString(_s.toString());
            var key = xpath_1.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
            var value = xpath_1.select("//*[local-name(.)='" + valueTag + "']/text()", xd);
            var res;
            if (key && key.length === 1 && utility_1.default.isNonEmptyArray(value)) {
                if (value.length === 1) {
                    res = value[0].nodeValue.toString();
                }
                else {
                    var dat_1 = [];
                    value.forEach(function (v) { return dat_1.push(String(v.nodeValue)); });
                    res = dat_1;
                }
                var objKey = key[0].nodeValue.toString();
                if (obj[objKey]) {
                    obj[objKey] = [obj[objKey]].concat(res);
                }
                else {
                    obj[objKey] = res;
                }
            }
            else {
                // console.warn('Multiple keys or null value is found');
            }
        });
        return Object.keys(obj).length === 0 ? undefined : obj;
    }
    /**
    * @private
    * @desc  Get the attribute according to the key
    * @param  {string} localName            tag name without prefix
    * @param  {string} localNameKey         key associated with tag name
    * @param  {string} attributeTag         tag of the attribute
    */
    function getAttributeKey(xmlDoc, localName, localNameKey, attributeTag) {
        var xpathStr = createXPath(localName);
        var selection = xpath_1.select(xpathStr, xmlDoc);
        var data = [];
        selection.forEach(function (_s) {
            var xd = new dom().parseFromString(_s.toString());
            var key = xpath_1.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
            var value = xpath_1.select("//*[local-name(.)='" + localName + "']/@" + attributeTag, xd);
            if (value && value.length === 1 && key && key.length === 1) {
                var obj = {};
                obj[key[0].nodeValue.toString()] = value[0].nodeValue.toString();
                data.push(obj);
            }
            else {
                //console.warn('Multiple keys or null value is found');
            }
        });
        return data.length === 0 ? undefined : data;
    }
    /**
    * @private
    * @desc Get the entire body according to the XPath
    * @param  {xml} xmlDoc              used xml document
    * @param  {string} localName        tag name without prefix
    * @param  {boolean} isOutputString  output is string format (default is true)
    * @return {string/array}
    */
    function getEntireBody(xmlDoc, localName, isOutputString) {
        var xpathStr = createXPath(localName);
        var selection = xpath_1.select(xpathStr, xmlDoc);
        if (selection.length === 0) {
            return undefined;
        }
        var data = [];
        selection.forEach(function (_s) {
            data.push(utility_1.default.convertToString(_s, isOutputString !== false));
        });
        return data.length === 1 ? data[0] : data;
    }
    /**
    * @private
    * @desc  Get the inner xml according to the XPath
    * @param  {xml} xmlDoc          used xml document
    * @param  {string} localName    tag name without prefix
    * @return {string/array} value
    */
    function getInnerText(xmlDoc, localName) {
        var xpathStr = createXPath(localName, true);
        var selection = xpath_1.select(xpathStr, xmlDoc);
        if (selection.length === 0) {
            return undefined;
        }
        var data = [];
        selection.forEach(function (_s) {
            data.push(String(_s.nodeValue).trim().replace(/\r?\n/g, ''));
        });
        return data.length === 1 ? data[0] : data;
    }
    /**
    * @public
    * @desc Create XPath
    * @param  {string/object} local     parameters to create XPath
    * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
    * @return {string} xpath
    */
    function createXPath(local, isExtractAll) {
        if (lodash_1.isObject(local)) {
            return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
        }
        return isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
    }
    /**
     * @private
     * @desc Tag normalization
     * @param {string} prefix     prefix of the tag
     * @param {content} content   normalize it to capitalized camel case
     * @return {string}
     */
    function tagging(prefix, content) {
        var camelContent = camel(content);
        return prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1);
    }
    return {
        createXPath: createXPath,
        getQueryParamByType: getQueryParamByType,
        defaultLoginRequestTemplate: defaultLoginRequestTemplate,
        defaultLoginResponseTemplate: defaultLoginResponseTemplate,
        defaultLogoutRequestTemplate: defaultLogoutRequestTemplate,
        defaultLogoutResponseTemplate: defaultLogoutResponseTemplate,
        /**
        * @desc Repalce the tag (e.g. {tag}) inside the raw XML
        * @param  {string} rawXML      raw XML string used to do keyword replacement
        * @param  {array} tagValues    tag values
        * @return {string}
        */
        replaceTagsByValue: function (rawXML, tagValues) {
            Object.keys(tagValues).forEach(function (t) {
                rawXML = rawXML.replace(new RegExp("{" + t + "}", 'g'), tagValues[t]);
            });
            return rawXML;
        },
        /**
        * @desc Helper function to build the AttributeStatement tag
        * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
        * @return {string}
        */
        attributeStatementBuilder: function (attributes) {
            var attr = attributes.map(function (_a) {
                var name = _a.name, nameFormat = _a.nameFormat, valueTag = _a.valueTag, valueXsiType = _a.valueXsiType;
                return "<saml:Attribute Name=\"" + name + "\" NameFormat=\"" + nameFormat + "\"><saml:AttributeValue xsi:type=\"" + valueXsiType + "\">{" + tagging('attr', valueTag) + "}</saml:AttributeValue></saml:Attribute>";
            }).join('');
            return "<saml:AttributeStatement>" + attr + "</saml:AttributeStatement>";
        },
        /**
        * @desc Construct the XML signature for POST binding
        * @param  {string} rawSamlMessage      request/response xml string
        * @param  {string} referenceTagXPath    reference uri
        * @param  {string} privateKey           declares the private key
        * @param  {string} passphrase           passphrase of the private key [optional]
        * @param  {string|buffer} signingCert   signing certificate
        * @param  {string} signatureAlgorithm   signature algorithm
        * @return {string} base64 encoded string
        */
        constructSAMLSignature: function (opts) {
            var rawSamlMessage = opts.rawSamlMessage, referenceTagXPath = opts.referenceTagXPath, privateKey = opts.privateKey, privateKeyPass = opts.privateKeyPass, _a = opts.signatureAlgorithm, signatureAlgorithm = _a === void 0 ? signatureAlgorithms.RSA_SHA256 : _a, signingCert = opts.signingCert, signatureConfig = opts.signatureConfig, _b = opts.isBase64Output, isBase64Output = _b === void 0 ? true : _b, _c = opts.isMessageSigned, isMessageSigned = _c === void 0 ? false : _c;
            var sig = new xml_crypto_1.SignedXml();
            // Add assertion sections as reference
            if (referenceTagXPath) {
                sig.addReference(referenceTagXPath, null, getDigestMethod(signatureAlgorithm));
            }
            if (isMessageSigned) {
                sig.addReference(
                // reference to the root node
                '/*', [
                    'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                    'http://www.w3.org/2001/10/xml-exc-c14n#',
                ], getDigestMethod(signatureAlgorithm), '', '', '', false);
            }
            sig.signatureAlgorithm = signatureAlgorithm;
            sig.keyInfoProvider = new this.getKeyInfo(signingCert, signatureConfig);
            sig.signingKey = utility_1.default.readPrivateKey(privateKey, privateKeyPass, true);
            if (signatureConfig) {
                sig.computeSignature(rawSamlMessage, signatureConfig);
            }
            else {
                sig.computeSignature(rawSamlMessage);
            }
            return isBase64Output !== false ? utility_1.default.base64Encode(sig.getSignedXml()) : sig.getSignedXml();
        },
        /**
        * @desc Verify the XML signature
        * @param  {string} xml xml
        * @param  {signature} signature context of XML signature
        * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
        * @return {boolean} verification result
        */
        verifySignature: function (xml, opts) {
            var _this = this;
            var doc = new dom().parseFromString(xml);
            var selection = xpath_1.select("//*[local-name(.)='Signature']", doc);
            // guarantee to have a signature in saml response
            if (selection.length === 0) {
                throw new Error('no signature is found in the context');
            }
            var sig = new xml_crypto_1.SignedXml();
            var res = true;
            xml = xml.replace(/<ds:Signature(.*?)>(.*?)<\/(.*?)ds:Signature>/g, '');
            selection.forEach(function (s) {
                var selectedCert = '';
                sig.signatureAlgorithm = opts.signatureAlgorithm;
                if (opts.keyFile) {
                    sig.keyInfoProvider = new xml_crypto_1.FileKeyInfo(opts.keyFile);
                }
                else if (opts.cert) {
                    var metadataCert = opts.cert.getX509Certificate(certUse.signing);
                    if (typeof metadataCert === 'string') {
                        metadataCert = [metadataCert];
                    }
                    else if (metadataCert instanceof Array) {
                        // flattens the nested array of Certificates from each KeyDescriptor
                        metadataCert = lodash_1.flattenDeep(metadataCert);
                    }
                    metadataCert = metadataCert.map(utility_1.default.normalizeCerString);
                    /*let x509Certificate = select(".//*[local-name(.)='X509Certificate']", s)[0].firstChild.data;
                    x509Certificate = utility.normalizeCerString(x509Certificate);
                    if (includes(metadataCert, x509Certificate)) {
                      selectedCert = x509Certificate;
                    }*/
                    var selectedCert_1 = metadataCert[0];
                    if (selectedCert_1 === '') {
                        throw new Error('certificate in document is not matched those specified in metadata');
                    }
                    sig.keyInfoProvider = new _this.getKeyInfo(selectedCert_1);
                }
                else {
                    throw new Error('undefined certificate in \'opts\' object');
                }
                sig.loadSignature(s);
                res = res && sig.checkSignature(xml);
            });
            return res;
        },
        /**
        * @desc High-level XML extractor
        * @param  {string} xmlString
        * @param  {object} fields
        */
        extractor: function (xmlString, fields) {
            var doc = new dom().parseFromString(xmlString);
            var meta = {};
            fields.forEach(function (field) {
                var objKey;
                var res;
                if (lodash_1.isString(field)) {
                    meta[field.toLowerCase()] = getInnerText(doc, field);
                }
                else if (typeof field === 'object') {
                    var localName = field.localName;
                    var extractEntireBody = field.extractEntireBody === true;
                    var attributes = field.attributes || [];
                    var customKey = field.customKey || '';
                    if (lodash_1.isString(localName)) {
                        objKey = localName;
                        if (extractEntireBody) {
                            res = getEntireBody(doc, localName);
                        }
                        else {
                            if (attributes.length !== 0) {
                                res = getAttributes(doc, localName, attributes);
                            }
                            else {
                                res = getInnerText(doc, localName);
                            }
                        }
                    }
                    else {
                        objKey = localName.tag;
                        if (field.attributeTag) {
                            res = getAttributeKey(doc, objKey, localName.key, field.attributeTag);
                        }
                        else if (field.valueTag) {
                            res = getInnerTextWithOuterKey(doc, objKey, localName.key, field.valueTag);
                        }
                    }
                    meta[customKey === '' ? objKey.toLowerCase() : customKey] = res;
                }
            });
            return meta;
        },
        /**
        * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
        * @param  {string} use          type of certificate (e.g. signing, encrypt)
        * @param  {string} certString    declares the certificate String
        * @return {object} object used in xml module
        */
        createKeySection: function (use, certString) {
            return {
                KeyDescriptor: [{
                        _attr: { use: use },
                    }, {
                        'ds:KeyInfo': [{
                                _attr: {
                                    'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                                },
                            }, {
                                'ds:X509Data': [{
                                        'ds:X509Certificate': utility_1.default.normalizeCerString(certString),
                                    }],
                            }],
                    }],
            };
        },
        /**
        * @desc Constructs SAML message
        * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
        * @param  {string} key                       declares the pem-formatted private key
        * @param  {string} passphrase                passphrase of private key [optional]
        * @param  {string} signingAlgorithm          signing algorithm
        * @return {string} message signature
        */
        constructMessageSignature: function (octetString, key, passphrase, isBase64, signingAlgorithm) {
            // Default returning base64 encoded signature
            // Embed with node-rsa module
            var decryptedKey = new nrsa(utility_1.default.readPrivateKey(key, passphrase), {
                signingScheme: getSigningScheme(signingAlgorithm),
            });
            var signature = decryptedKey.sign(octetString);
            // Use private key to sign data
            return isBase64 !== false ? signature.toString('base64') : signature;
        },
        /**
        * @desc Verifies message signature
        * @param  {Metadata} metadata                 metadata object of identity provider or service provider
        * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
        * @param  {string} signature                  context of XML signature
        * @param  {string} verifyAlgorithm            algorithm used to verify
        * @return {boolean} verification result
        */
        verifyMessageSignature: function (metadata, octetString, signature, verifyAlgorithm) {
            var signCert = metadata.getX509Certificate(certUse.signing);
            var signingScheme = getSigningScheme(verifyAlgorithm);
            var key = new nrsa(utility_1.default.getPublicKeyPemFromCertificate(signCert), { signingScheme: signingScheme });
            return key.verify(new Buffer(octetString), signature);
        },
        /**
        * @desc Get the public key in string format
        * @param  {string} x509Certificate certificate
        * @return {string} public key
        */
        getKeyInfo: function (x509Certificate, signatureConfig) {
            if (signatureConfig === void 0) { signatureConfig = {}; }
            this.getKeyInfo = function (key) {
                var prefix = signatureConfig.prefix ? signatureConfig.prefix + ":" : '';
                return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + x509Certificate + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
            };
            this.getKey = function (keyInfo) {
                return utility_1.default.getPublicKeyPemFromCertificate(x509Certificate).toString();
            };
        },
        /**
        * @desc Encrypt the assertion section in Response
        * @param  {Entity} sourceEntity             source entity
        * @param  {Entity} targetEntity             target entity
        * @param  {string} xml                      response in xml string format
        * @return {Promise} a promise to resolve the finalized xml
        */
        encryptAssertion: function (sourceEntity, targetEntity, xml) {
            // Implement encryption after signature if it has
            return new Promise(function (resolve, reject) {
                if (xml) {
                    var sourceEntitySetting_1 = sourceEntity.entitySetting;
                    var targetEntitySetting = targetEntity.entitySetting;
                    var sourceEntityMetadata = sourceEntity.entityMeta;
                    var targetEntityMetadata = targetEntity.entityMeta;
                    var doc_1 = new dom().parseFromString(xml);
                    var assertions_1 = xpath_1.select("//*[local-name(.)='Assertion']", doc_1);
                    var assertionNode = getEntireBody(new dom().parseFromString(xml), 'Assertion');
                    if (!Array.isArray(assertions_1)) {
                        throw new Error('undefined assertion is found');
                    }
                    if (assertions_1.length !== 1) {
                        throw new Error("undefined number (" + assertions_1.length + ") of assertion section");
                    }
                    // Perform encryption depends on the setting, default is false
                    if (sourceEntitySetting_1.isAssertionEncrypted) {
                        xmlenc.encrypt(assertions_1[0].toString(), {
                            // use xml-encryption module
                            rsa_pub: new Buffer(utility_1.default.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt)).replace(/\r?\n|\r/g, '')),
                            pem: new Buffer('-----BEGIN CERTIFICATE-----' + targetEntityMetadata.getX509Certificate(certUse.encrypt) + '-----END CERTIFICATE-----'),
                            encryptionAlgorithm: sourceEntitySetting_1.dataEncryptionAlgorithm,
                            keyEncryptionAlgorighm: sourceEntitySetting_1.keyEncryptionAlgorithm,
                        }, function (err, res) {
                            if (err) {
                                return reject(new Error('exception in encrpytedAssertion ' + err));
                            }
                            if (!res) {
                                return reject(new Error('undefined encrypted assertion'));
                            }
                            var encAssertionPrefix = sourceEntitySetting_1.tagPrefix.encryptedAssertion;
                            var encryptAssertionNode = new dom().parseFromString("<" + encAssertionPrefix + ":EncryptedAssertion xmlns:" + encAssertionPrefix + "=\"" + urn_1.namespace.names.assertion + "\">" + res + "</" + encAssertionPrefix + ":EncryptedAssertion>");
                            doc_1.replaceChild(encryptAssertionNode, assertions_1[0]);
                            return resolve(utility_1.default.base64Encode(doc_1.toString()));
                        });
                    }
                    else {
                        return resolve(utility_1.default.base64Encode(xml)); // No need to do encrpytion
                    }
                }
                else {
                    return reject(new Error('empty or undefined xml string during encryption'));
                }
            });
        },
        /**
        * @desc Decrypt the assertion section in Response
        * @param  {string} type             only accept SAMLResponse to proceed decryption
        * @param  {Entity} here             this entity
        * @param  {Entity} from             from the entity where the message is sent
        * @param {string} entireXML         response in xml string format
        * @return {function} a promise to get back the entire xml with decrypted assertion
        */
        decryptAssertion: function (here, entireXML) {
            return new Promise(function (resolve, reject) {
                // Implement decryption first then check the signature
                if (!entireXML) {
                    return reject(new Error('empty or undefined xml string during decryption'));
                }
                // Perform encryption depends on the setting of where the message is sent, default is false
                var hereSetting = here.entitySetting;
                var xml = new dom().parseFromString(entireXML);
                var encryptedAssertions = xpath_1.select("//*[local-name(.)='EncryptedAssertion']", xml);
                if (!Array.isArray(encryptedAssertions)) {
                    throw new Error('undefined encrypted assertion is found');
                }
                if (encryptedAssertions.length !== 1) {
                    throw new Error("undefined number (" + encryptedAssertions.length + ") of encrypted assertions section");
                }
                return xmlenc.decrypt(encryptedAssertions[0].toString(), {
                    key: utility_1.default.readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass),
                }, function (err, res) {
                    if (err) {
                        return reject(new Error('exception in decryptAssertion ' + err));
                    }
                    if (!res) {
                        return reject(new Error('undefined encrypted assertion'));
                    }
                    var assertionNode = new dom().parseFromString(res);
                    xml.replaceChild(assertionNode, encryptedAssertions[0]);
                    return resolve(xml.toString());
                });
            });
        },
        /**
         * @desc Check if the xml string is valid and bounded
         */
        isValidXml: function (input) {
            return __awaiter(this, void 0, void 0, function () {
                return __generator(this, function (_a) {
                    return [2 /*return*/, new Promise(function (resolve, reject) {
                            // https://github.com/albanm/node-libxml-xsd/issues/11
                            var currentDirectory = path.resolve('');
                            process.chdir(path.resolve(__dirname, '../schemas'));
                            xsd.parseFile(path.resolve('saml-schema-protocol-2.0.xsd'), function (err, schema) {
                                if (err) {
                                    return reject(err.message);
                                }
                                schema.validate(input, function (techErrors, validationErrors) {
                                    if (techErrors !== null || validationErrors !== null) {
                                        return reject("this is not a valid saml response with errors: " + validationErrors);
                                    }
                                    return resolve(true);
                                });
                            });
                        })];
                });
            });
        },
    };
};
exports.default = libSaml();
//# sourceMappingURL=libsaml.js.map