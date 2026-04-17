/**
 Copyright 2023 Sal Rahman

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * Encodes an array buffer as a base64 string
 * @param buffer An array buffer to encode
 * @returns A base64 encoded string
 */
function encodeBase64(buffer) {
    const base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    const bytes = new Uint8Array(buffer);
    let i = 0;
    let base64 = "";
    while (i < bytes.length) {
        const byte1 = bytes[i++] || 0;
        let byte2 = bytes[i++];
        let byte3 = bytes[i++];
        let padding = 0;
        if (byte2 === undefined) {
            padding++;
            byte2 = 0;
        }
        if (byte3 === undefined) {
            padding++;
            byte3 = 0;
        }
        const encoded1 = byte1 >> 2;
        const encoded2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
        let encoded3 = ((byte2 & 0x0f) << 2) | (byte3 >> 6);
        let encoded4 = byte3 & 0x3f;
        if (padding === 1)
            encoded4 = 64;
        if (padding === 2)
            encoded3 = encoded4 = 64;
        base64 += `${base64chars[encoded1]}${base64chars[encoded2]}${base64chars[encoded3]}${base64chars[encoded4]}`;
    }
    return base64;
}

/**
 * Decodes a base64 string into an array buffer
 * @param base64 A base64 encoded string
 * @returns An array buffer
 */
function decodeBase64(base64) {
    const base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!base64.match(/^[A-Za-z0-9+/]+={0,2}$/)) {
        throw new Error("Invalid base64 string");
    }
    const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
    const bytes = new Uint8Array((base64.length * 6) / 8 - padding);
    let i = 0;
    let j = 0;
    while (i < base64.length) {
        const index1 = base64chars.indexOf(base64[i++] ?? '.');
        const index2 = base64chars.indexOf(base64[i++] ?? '.');
        const index3 = base64chars.indexOf(base64[i++] ?? '.');
        const index4 = base64chars.indexOf(base64[i++] ?? '.');
        const decoded1 = (index1 << 2) | (index2 >> 4);
        const decoded2 = ((index2 & 0x0f) << 4) | (index3 >> 2);
        const decoded3 = ((index3 & 0x03) << 6) | index4;
        bytes[j++] = decoded1;
        if (index3 !== 64) {
            bytes[j++] = decoded2;
        }
        if (index4 !== 64) {
            bytes[j++] = decoded3;
        }
    }
    return bytes.buffer;
}


ITUDRMLicense = class ITUDRMLicense {
    constructor(Base64license) {
        this.hasMore = () => this.index < this.data.length;
        this.alwaysRead = (ix) => this.data[ix] ?? 0xFF;
        this.readUint8 = () => this.alwaysRead(this.index++);
        this.readUint16 = () => {
            const value = (this.alwaysRead(this.index) << 8 | (this.alwaysRead(this.index + 1)));
            this.index += 2;
            return value;
        };
        this.readUint32 = () => {
            const value = (this.alwaysRead(this.index) << 24 | this.alwaysRead(this.index + 1) << 16 | this.alwaysRead(this.index + 2) << 8 | this.alwaysRead(this.index + 3));
            this.index += 4;
            return value;
        };
        this.readUint64 = () => {
            let value = BigInt(0);
            for (let i = 0; i < 8; i++) {
                value = (value << BigInt(8)) | BigInt(this.alwaysRead(this.index++));
            }
            return value;
        };
        this.readString = (length) => {
            const str = this.data.slice(this.index, this.index + length);
            this.index += length;
            return str;
        };
        this.skip = (numToSkip) => this.index += numToSkip;
        this.toBase64 = (str) => encodeBase64(str.buffer);
        this.fromBase64 = (str) => new Uint8Array(decodeBase64(str));
        this.isASCII = (str) => {
            for (let i = 0; i < str.length; i++)
                if ((str[i] ?? 0xFF) < 0x20 || (str[i] ?? 0xFF) > 0x7E)
                    return false;
            return true;
        };
        this.toASCII = (str) => {
            let res = "";
            for (let i = 0; i < str.length; i++)
                res += String.fromCharCode(str[i] || '.'.charCodeAt(0));
            return res;
        };
        this.AsciiOrBase64 = (str) => this.isASCII(str) ? this.toASCII(str) : `{${this.toBase64(str)}}`;
        this.Reserved = (id) => `Reserved [0x${Math.abs(id).toString(16)}]`;
        this.index = 0;
        this.data = this.fromBase64(Base64license);
    }
    lookupAlgorithm(algId) {
        switch (algId) {
            case 0x02: return "HashAlgorithm:SM3";
            case 0x12: return "PublicKeyAlgorithm:SM2";
            case 0x21: return "BlockCipherAlgorithm:SM4-CBC";
            case 0x22: return "BlockCipherAlgorithm:SM4-ECB";
            case 0x23: return "BlockCipherAlgorithm:SM4-CTR";
            case 0x42: return "SignatureAlgorithm:SM2";
            case 0x43: return "HMAC-SM3";
        }
        if ((algId & 0x0f) >= 0b1010 && (algId & 0x0f) <= 0b1111)
            return "User defined";
        return this.Reserved(algId);
    }
    lookupKeyType(keyTypeId) {
        switch (keyTypeId) {
            case 0x01: return "Content Key";
            case 0x03: return "Device Key";
            case 0x20: return "Session Key";
            case 0x21: return "HMAC Key";
        }
        return this.Reserved(keyTypeId);
    }
    lookupKeyUsageRuleType(ruleTypeId) {
        switch (ruleTypeId) {
            case 0x01: return "Start time";
            case 0x02: return "End time";
            case 0x03: return "Number of uses";
            case 0x04: return "Time period";
            case 0x05: return "Cumulative time period";
            case 0x06: return "Output rules";
            case 0x07: return "Client Security Level requirements";
            case 0xF0: return "Digital watermark data";
            case 0xF1: return "Key storage rule";
            case 0xF2: return "Latest playback start interval";
            case 0xF3: return "Allow license update";
            case 0xF4: return "License update URL";
            case 0xF5: return "License update start interval";
            case 0xF6: return "License update retry interval";
        }
        return this.Reserved(ruleTypeId);
    }
    parseKeyRule(KeyRuleType, KeyRuleData) {
        const alwaysValue = (index) => KeyRuleData[index] ?? 0xFF;
        switch (KeyRuleType) {
            case 0x01: // Start time  
                const startTime = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return new Date(startTime * 1000).toISOString();
            case 0x02: // End time
                const endTime = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return new Date(endTime * 1000).toISOString();
            case 0x03: // Number of uses
                const numUses = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return numUses.toString();
            case 0x04: // Time period
                const timePeriod = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return timePeriod.toString();
            case 0x05: // Time period
                const cumulativeTimePeriod = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return cumulativeTimePeriod.toString();
            case 0x06: // Output rules
                const ruleCode = alwaysValue(0);
                let res = "Analog output ";
                switch ((ruleCode & 0b11110000) >> 4) {
                    case 0b0000:
                        res += "No limit";
                        break;
                    case 0b0001:
                        res += "Disabled";
                        break;
                    default:
                        res += this.Reserved((ruleCode & 0b11110000) >> 4);
                        break;
                }
                res += ", Digital output: ";
                switch (ruleCode & 0b00001111) {
                    case 0b0000:
                        res += "No limit";
                        break;
                    case 0b0001:
                        res += "Only HDCP1.4 and above";
                        break;
                    case 0b0010:
                        res += "Only HDCP2.2 and above";
                        break;
                    case 0b0011:
                        res += "Disabled";
                        break;
                    case 0b0100:
                        res += "ADCP L1 and above";
                        break;
                    case 0b0101:
                        res += "ADCP L2 and above";
                        break;
                    case 0b0110:
                        res += "ADCP L3 and above";
                        break;
                    default:
                        res += this.Reserved(ruleCode & 0x0f);
                        break;
                }
                return res;
            case 0x07: // Client Security Level requirements    
                const req = alwaysValue(0);
                switch (req) {
                    case 0x01: return "Software Security Level";
                    case 0x02: return "Hardware Security Level";
                    case 0x03: return "Enhanced Hardware Security Level";
                }
                return this.Reserved(req);
            case 0xF0: // Digital watermark data
                const watermarkData = this.AsciiOrBase64(KeyRuleData);
                return `Digital watermark data: ${watermarkData}`;
            case 0xF1: // Key storage rule
                const storage = alwaysValue(0);
                return `Local storage is ${(storage == 0x01 ? "" : "not ")}allowed`;
            case 0xF2: // Latest playback start interval
                const interval = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `Latest playback start interval: ${interval} seconds`;
            case 0xF3: // Allow license update
                const allowUpdate = alwaysValue(0);
                return `License update is ${(allowUpdate == 0x01 ? "" : "not ")}allowed`;
            case 0xF4: // License update URL
                const url = this.AsciiOrBase64(KeyRuleData);
                return `License update URL: ${url}`;
            case 0xF5: // License update start interval
                const startInterval = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `License update start interval: ${startInterval} seconds`;
            case 0xF6: // License update retry interval
                const retryInterval = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `License update retry interval: ${retryInterval} seconds`;
        }
        return this.AsciiOrBase64(KeyRuleData);
    }
    describeUnitType(unitType) {
        switch (unitType) {
            case 0x00: return "License index";
            case 0x01: return "Content";
            case 0x02: return "Authorized object";
            case 0x03: return "Key";
            case 0x04: return "Key usage rule";
            case 0xFF: return "License verification data";
        }
        return this.Reserved(unitType);
    }
    asString(asHTML = false) {
        let res = "";
        this.index = 0;
        while (this.hasMore()) {
            const ident_type = this.readUint8();
            const ident_index = this.readUint8();
            const ident_length = this.readUint16();
            res += asHTML 
             ? `<div class="license-unit"><span class="unit-type">Type: ${ident_type} (${this.describeUnitType(ident_type)})</span>, <span class="unit-index">Index: ${ident_index}</span>, <span class="unit-length">Length: ${ident_length}</span><br>`
             : `Type: ${ident_type} (${this.describeUnitType(ident_type)}), Index: ${ident_index}, Length: ${ident_length}\n`;
            switch (ident_type) {
                case 0x00: // License index
                    const licenseVersion = this.readUint8();
                    const licenseId = this.readUint64();
                    const licenseUnitsCount = this.readUint8();
                    const licenseTimestamp = this.readUint32();
                    res += asHTML 
                     ? `<div><span class="license-version">License Version: ${licenseVersion}</span>, <span class="license-id">License ID: ${licenseId}</span>, <span class="license-units-count">License Units Count: ${licenseUnitsCount}</span>, <span class="license-timestamp">License Timestamp: ${new Date(licenseTimestamp * 1000).toISOString()}</span><br></div>`
                     : ` License Version: ${licenseVersion}, License ID: ${licenseId}, License Units Count: ${licenseUnitsCount}, License Timestamp: ${new Date(licenseTimestamp * 1000).toISOString()}\n`;
                    break;
                case 0x01: // Content
                    const contentIdLen = this.readUint8();
                    const contentId = this.readString(contentIdLen);
                    res += asHTML 
                     ? `<div><span class="content-id">Content ID: ${this.AsciiOrBase64(contentId)}</span><br></div>`
                     : ` Content ID: ${this.AsciiOrBase64(contentId)}\n`;
                    const CEKCount = this.readUint8();
                    for (let k = 0; k < CEKCount; k++) {
                        const KeyIdentifierLen = this.readUint8();
                        const KeyIdentifier = this.readString(KeyIdentifierLen);
                        res += asHTML 
                         ? `<div><span class="key-identifier">Key Identifier[${k + 1}]: ${this.AsciiOrBase64(KeyIdentifier)}</span><br></div>`
                         : ` Key Identifier[${k + 1}]: ${this.AsciiOrBase64(KeyIdentifier)}\n`;
                    }
                    break;
                case 0x02: // Authorized object
                    const ObjectType = this.readUint8();
                    const ObjectId = this.readString(ident_length - 1);
                    res += asHTML 
                     ? `<div><span class="object-type">Object Type: ${ObjectType}</span>, <span class="object-id">Object Id: ${this.AsciiOrBase64(ObjectId)}</span><br></div>`
                     : ` Object Type: ${ObjectType}, Object Id: ${this.AsciiOrBase64(ObjectId)}\n`;
                    break;
                case 0x03: // Key
                    const KeyAlgorithm = this.readUint8();
                    const KeyDataLen = this.readUint16();
                    const KeyData = this.readString(KeyDataLen);
                    res += asHTML
                     ? `<div><span class="key-algorithm">Key Algorithm: ${KeyAlgorithm} (${this.lookupAlgorithm(KeyAlgorithm)})</span>, <span class="key-data">Key Data: ${this.AsciiOrBase64(KeyData)}</span><br></div>`
                     : ` Key Algorithm: ${KeyAlgorithm} (${this.lookupAlgorithm(KeyAlgorithm)}), Key Data: ${this.AsciiOrBase64(KeyData)}\n`;
                    const KeyType = this.readUint8();
                    const KeyIdentifierLen = this.readUint8();
                    const KeyIdentifier = this.readString(KeyIdentifierLen);
                    res += asHTML 
                     ? `<div><span class="key-type">Key Type: ${KeyType} (${this.lookupKeyType(KeyType)})</span>, <span class="key-identifier">Key Identifier: ${this.AsciiOrBase64(KeyIdentifier)}</span><br></div>`
                     : ` Key Type: ${KeyType} (${this.lookupKeyType(KeyType)}), Key Identifier: ${this.AsciiOrBase64(KeyIdentifier)}\n`;
                    const UpperKeyType = this.readUint8();
                    const UpperKeyIdentifierLen = this.readUint8();
                    const UpperKeyIdentifier = this.readString(UpperKeyIdentifierLen);
                    res += asHTML
                     ? `<div><span class="upper-key-type">Upper Key Type: ${UpperKeyType} (${this.lookupKeyType(UpperKeyType)})</span>, <span class="upper-key-identifier">Upper Key Identifier: ${this.AsciiOrBase64(UpperKeyIdentifier)}</span><br></div>`
                     : ` Upper Key Type: ${UpperKeyType} (${this.lookupKeyType(UpperKeyType)}), Upper Key Identifier: ${this.AsciiOrBase64(UpperKeyIdentifier)}\n`;
                    break;
                case 0x04: // Key usage rule
                    const KeyType4 = this.readUint8();
                    const KeyIdentifierLen4 = this.readUint8();
                    const KeyIdentifier4 = this.readString(KeyIdentifierLen4);
                    res += asHTML
                     ? `<div><span class="key-type">Key Type: ${KeyType4} (${this.lookupKeyType(KeyType4)})</span>, <span class="key-identifier">Key Identifier: ${this.AsciiOrBase64(KeyIdentifier4)}</span><br></div>`
                     : ` Key Type: ${KeyType4} (${this.lookupKeyType(KeyType4)}), Key Identifier: ${this.AsciiOrBase64(KeyIdentifier4)}\n`;
                    const KeyRulesNum = this.readUint8();
                    for (let r = 0; r < KeyRulesNum; r++) {
                        const KeyRuleType = this.readUint8();
                        const KeyRuleLen = this.readUint8();
                        const KeyRuleData = this.readString(KeyRuleLen);
                        res += asHTML
                         ? `<div><span class="key-rule">Key Rule[${r + 1}]: Type: ${KeyRuleType} (${this.lookupKeyUsageRuleType(KeyRuleType)}), Data: ${this.parseKeyRule(KeyRuleType, KeyRuleData)}</span><br></div>`
                         : ` Key Rule[${r + 1}]: Type: ${KeyRuleType} (${this.lookupKeyUsageRuleType(KeyRuleType)}), Data: ${this.parseKeyRule(KeyRuleType, KeyRuleData)}\n`;
                    }
                    break;
                case 0xFF: // License verification data
                    const Algorithm = this.readUint8();
                    const KeyIDLength = this.readUint8();
                    const KeyID = this.readString(KeyIDLength);
                    const SignatureLength = this.readUint16();
                    const Signature = this.readString(SignatureLength);
                    res += asHTML
                     ? `<div><span class="algorithm">Algorithm: ${Algorithm} (${this.lookupAlgorithm(Algorithm)})</span>, <span class="key-id">Key ID: ${this.AsciiOrBase64(KeyID)}</span>, <span class="signature">Signature: ${this.AsciiOrBase64(Signature)}</span><br></div>`
                     : ` Algorithm: ${Algorithm} (${this.lookupAlgorithm(Algorithm)}), Key ID: ${this.AsciiOrBase64(KeyID)}, Signature: ${this.AsciiOrBase64(Signature)}`;
                    break;
                default:
                    res += `Reserved Unit Type: ${ident_type}  (see ITU-T J.1041 table 8-1)\n`;
                    this.skip(ident_length);
                    break;
            }
            if (asHTML) res += `</div>`;
        }
        return res;
    }
}
