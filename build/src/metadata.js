"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
* @file metadata.ts
* @author tngan
* @desc An abstraction for metadata of identity provider and service provider
*/
var libsaml_1 = require("./libsaml");
var fs = require("fs");
var urn_1 = require("./urn");
var lodash_1 = require("lodash");
var certUse = urn_1.wording.certUse;
var Metadata = /** @class */ (function () {
    /**
    * @param  {string | Buffer} metadata xml
    * @param  {object} extraParse for custom metadata extractor
    */
    function Metadata(xml, extraParse) {
        if (extraParse === void 0) { extraParse = []; }
        this.xmlString = xml.toString();
        this.meta = libsaml_1.default.extractor(this.xmlString, extraParse.concat(['NameIDFormat', {
                localName: 'EntityDescriptor', attributes: ['entityID'],
            }, {
                localName: { tag: 'KeyDescriptor', key: 'use' },
                valueTag: 'X509Certificate',
            }, {
                localName: { tag: 'SingleLogoutService', key: 'Binding' },
                attributeTag: 'Location',
            }]));
        if (!this.meta.entitydescriptor || Array.isArray(this.meta.entitydescriptor)) {
            throw new Error('metadata must contain exactly one entity descriptor');
        }
    }
    /**
    * @desc Get the metadata in xml format
    * @return {string} metadata in xml format
    */
    Metadata.prototype.getMetadata = function () {
        return this.xmlString;
    };
    /**
    * @desc Export the metadata to specific file
    * @param {string} exportFile is the output file path
    */
    Metadata.prototype.exportMetadata = function (exportFile) {
        fs.writeFileSync(exportFile, this.xmlString);
    };
    /**
    * @desc Get the entityID in metadata
    * @return {string} entityID
    */
    Metadata.prototype.getEntityID = function () {
        return this.meta.entitydescriptor.entityid;
    };
    /**
    * @desc Get the x509 certificate declared in entity metadata
    * @param  {string} use declares the type of certificate
    * @return {string} certificate in string format
    */
    Metadata.prototype.getX509Certificate = function (use) {
        if (use === certUse.signing || use === certUse.encrypt) {
            return this.meta.keydescriptor[use];
        }
        throw new Error('undefined use of key in getX509Certificate');
    };
    /**
    * @desc Get the support NameID format declared in entity metadata
    * @return {array} support NameID format
    */
    Metadata.prototype.getNameIDFormat = function () {
        return this.meta.nameidformat;
    };
    /**
    * @desc Get the entity endpoint for single logout service
    * @param  {string} binding e.g. redirect, post
    * @return {string/object} location
    */
    Metadata.prototype.getSingleLogoutService = function (binding) {
        if (lodash_1.isString(binding)) {
            var bindType_1 = urn_1.namespace.binding[binding];
            var service = this.meta.singlelogoutservice.find(function (obj) { return obj[bindType_1]; });
            if (service) {
                return service[bindType_1];
            }
        }
        return this.meta.singlelogoutservice;
    };
    /**
    * @desc Get the support bindings
    * @param  {[string]} services
    * @return {[string]} support bindings
    */
    Metadata.prototype.getSupportBindings = function (services) {
        var supportBindings = [];
        if (services) {
            services.forEach(function (service) { return supportBindings.push(Object.keys(service)[0]); });
        }
        return supportBindings;
    };
    return Metadata;
}());
exports.default = Metadata;
//# sourceMappingURL=metadata.js.map