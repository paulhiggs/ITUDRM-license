import { encodeBase64, decodeBase64 } from "./base64.mts";

export class ITUDRMLicense {
    private index: number;
    private data: Uint8Array;

    constructor(Base64license: string) {
        this.index = 0;
        this.data = this.fromBase64(Base64license);
    }

    private hasMore = (): boolean => this.index < this.data.length;

    private alwaysRead = (ix:number): number => this.data[ix] ?? 0xFF;

    private readUint8 = (): number => this.alwaysRead(this.index++);

    private readUint16 = (): number => {
        const value = (this.alwaysRead(this.index) << 8 | (this.alwaysRead(this.index+1)));
        this.index += 2;
        return value;
    }

    private readUint32 = (): number => {
        const value = (this.alwaysRead(this.index) << 24 | this.alwaysRead(this.index+1) << 16 | this.alwaysRead(this.index+2) << 8 | this.alwaysRead(this.index+3));
        this.index+=4;
        return value;
    }

    private readUint64 = (): BigInt => {
        let value = BigInt(0);
        for (let i=0; i<8; i++) {
            value = (value << BigInt(8)) | BigInt(this.alwaysRead(this.index++));
        }
        return value;
    }

    private readString = (length: number): Uint8Array => {
        const str = this.data.slice(this.index, this.index+length);
        this.index+=length;
        return str;
    }

    private skip = (numToSkip: number) => this.index += numToSkip;

    private toBase64 = (str: Uint8Array<ArrayBuffer>):string => encodeBase64(str.buffer);
    private fromBase64 = (str: string):Uint8Array => new Uint8Array(decodeBase64(str));

    private isASCII = (str: Uint8Array): boolean => {
        for (let i = 0; i < str.length; i++) 
            if ((str[i] ?? 0xFF) < 0x20 || (str[i] ?? 0xFF) > 0x7E) return false;
        return true;
    }

    private  toASCII = (str: Uint8Array): string => {
        let res = "";   
        for (let i = 0; i < str.length; i++) res += String.fromCharCode(str[i] || '.'.charCodeAt(0));
        return res;
    }

    private AsciiOrBase64 = (str: Uint8Array): string => this.isASCII(str) ? this.toASCII(str) : `{${this.toBase64(str as Uint8Array<ArrayBuffer>)}}`;

    private Reserved = (id: number): string => `Reserved [0x${Math.abs(id).toString(16)}]`;

    private lookupAlgorithm(algId: number): string {
        switch (algId) {
            case 0x02: return "HashAlgorithm:SM3";
            case 0x12: return "PublicKeyAlgorithm:SM2";
            case 0x21: return "BlockCipherAlgorithm:SM4-CBC";
            case 0x22: return "BlockCipherAlgorithm:SM4-ECB";
            case 0x23: return "BlockCipherAlgorithm:SM4-CTR";
            case 0x42: return "SignatureAlgorithm:SM2";
            case 0x43: return "HMAC-SM3";
        }
        if ((algId & 0x0f) >= 0b1010 && (algId & 0x0f) <= 0b1111) return "User defined";
        return this.Reserved(algId);
    }

    private lookupKeyType(keyTypeId: number): string {
        switch (keyTypeId) {
            case 0x01: return "Content Key";  
            case 0x03: return "Device Key";
            case 0x20: return "Session Key";
            case 0x21: return "HMAC Key";
        }
        return this.Reserved(keyTypeId);
    }

    private lookupKeyUsageRuleType(ruleTypeId: number): string {
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

    private parseKeyRule(KeyRuleType: number, KeyRuleData : Uint8Array): string {
        const alwaysValue = (index:number): number => KeyRuleData[index] ?? 0xFF;
        switch (KeyRuleType) {
            case 0x01: // Start time  
                const startTime : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return new Date(startTime * 1000).toISOString();
            case 0x02: // End time
                const endTime : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return new Date(endTime * 1000).toISOString();
            case 0x03: // Number of uses
                const numUses : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return numUses.toString();
            case 0x04: // Time period
                const timePeriod : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return timePeriod.toString();
            case 0x05: // Time period
                const cumulativeTimePeriod : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return cumulativeTimePeriod.toString();
            case 0x06: // Output rules
                const ruleCode : number =alwaysValue(0);
                let res = "Analog output ";
                switch ((ruleCode & 0b11110000) >>4) {
                    case 0b0000: res += "No limit"; break;
                    case 0b0001: res += "Disabled"; break;
                    default: res += this.Reserved((ruleCode & 0b11110000) >>4); break;
                }   
                res += ", Digital output: ";
                switch (ruleCode & 0b00001111) {
                    case 0b0000: res += "No limit"; break;
                    case 0b0001: res += "Only HDCP1.4 and above"; break;
                    case 0b0010: res += "Only HDCP2.2 and above"; break;
                    case 0b0011: res += "Disabled"; break;
                    case 0b0100: res += "ADCP L1 and above"; break;
                    case 0b0101: res += "ADCP L2 and above"; break;
                    case 0b0110: res += "ADCP L3 and above"; break;
                    default: res += this.Reserved(ruleCode & 0x0f); break;
                }
                return res;
            case 0x07: // Client Security Level requirements    
                const  req : number = alwaysValue(0);
                switch (req) {
                    case 0x01: return "Software Security Level";
                    case 0x02: return "Hardware Security Level";
                    case 0x03: return "Enhanced Hardware Security Level";
                }
                return this.Reserved(req);
            case 0xF0: // Digital watermark data
                const watermarkData : string = this.AsciiOrBase64(KeyRuleData);
                return `Digital watermark data: ${watermarkData}`;
            case 0xF1: // Key storage rule
                const storage : number = alwaysValue(0);
                return `Local storage is ${(storage == 0x01 ? "" : "not ")}allowed`;
            case 0xF2: // Latest playback start interval
                const interval : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `Latest playback start interval: ${interval} seconds`;   
            case 0xF3: // Allow license update
                const allowUpdate : number = alwaysValue(0);
                return `License update is ${(allowUpdate == 0x01 ? "" : "not ")}allowed`;   
            case 0xF4: // License update URL
                const url : string = this.AsciiOrBase64(KeyRuleData);
                return `License update URL: ${url}`;
            case 0xF5: // License update start interval
                const startInterval : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `License update start interval: ${startInterval} seconds`;
            case 0xF6: // License update retry interval
                const retryInterval : number = alwaysValue(0) << 24 | alwaysValue(1) << 16 | alwaysValue(2) << 8 | alwaysValue(3);
                return `License update retry interval: ${retryInterval} seconds`;
        }   
        return this.AsciiOrBase64(KeyRuleData);
    }

    private describeUnitType(unitType: number): string {
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


    asString(): string {
        let res = "";
        this.index = 0;

        while (this.hasMore()) {
            const ident_type = this.readUint8();
            const ident_index = this.readUint8();
            const ident_length = this.readUint16();

            res+=`Type: ${ident_type} (${this.describeUnitType(ident_type)}), Index: ${ident_index}, Length: ${ident_length}\n`;

            switch (ident_type) {
                case 0x00: // License index
                    const licenseVersion = this.readUint8();
                    const licenseId = this.readUint64();
                    const licenseUnitsCount = this.readUint8();
                    const licenseTimestamp = this.readUint32();
                    res+=` License Version: ${licenseVersion}, License ID: ${licenseId}, License Units Count: ${licenseUnitsCount}, License Timestamp: ${new Date(licenseTimestamp * 1000).toISOString()}\n`;
                    break;
                case 0x01: // Content
                    const contentIdLen = this.readUint8();
                    const contentId = this.readString(contentIdLen);
                    res+=` Content ID: ${this.AsciiOrBase64(contentId)}\n`;
                    const CEKCount = this.readUint8();
                    for (let k=0; k<CEKCount; k++) {
                        const KeyIdentifierLen = this.readUint8();
                        const KeyIdentifier = this.readString(KeyIdentifierLen);
                        res+=` Key Identifier[${k+1}]: ${this.AsciiOrBase64(KeyIdentifier)}\n`;
                    }
                    break;
                case 0x02: // Authorized object
                    const ObjectType = this.readUint8();
                    const ObjectId = this.readString(ident_length-1);
                    res+=` Object Type: ${ObjectType}, Object Id: ${this.AsciiOrBase64(ObjectId)}\n`;
                    break;
                case 0x03: // Key
                    const KeyAlgorithm = this.readUint8();
                    const KeyDataLen = this.readUint16();
                    const KeyData = this.readString(KeyDataLen);
                    res+=` Key Algorithm: ${KeyAlgorithm} (${this.lookupAlgorithm(KeyAlgorithm)}), Key Data: ${this.AsciiOrBase64(KeyData)}\n`;
                    const KeyType = this.readUint8();
                    const KeyIdentifierLen = this.readUint8();
                    const KeyIdentifier = this.readString(KeyIdentifierLen);
                    res+=` Key Type: ${KeyType} (${this.lookupKeyType(KeyType)}), Key Identifier: ${this.AsciiOrBase64(KeyIdentifier)}\n`;
                    const UpperKeyType = this.readUint8();
                    const UpperKeyIdentifierLen = this.readUint8();
                    const UpperKeyIdentifier = this.readString(UpperKeyIdentifierLen);
                    res+=` Upper Key Type: ${UpperKeyType} (${this.lookupKeyType(UpperKeyType)}), Upper Key Identifier: ${this.AsciiOrBase64(UpperKeyIdentifier)}\n`;
                    break;
                case 0x04: // Key usage rule
                    const KeyType4 = this.readUint8();
                    const KeyIdentifierLen4 = this.readUint8();
                    const KeyIdentifier4 = this.readString(KeyIdentifierLen4);
                    res+=` Key Type: ${KeyType4} (${this.lookupKeyType(KeyType4)}), Key Identifier: ${this.AsciiOrBase64(KeyIdentifier4)}\n`;
                    const KeyRulesNum = this.readUint8();
                    for (let r=0; r<KeyRulesNum; r++) {
                        const KeyRuleType = this.readUint8();
                        const KeyRuleLen = this.readUint8();
                        const KeyRuleData = this.readString(KeyRuleLen);
                        res+=` Key Rule[${r+1}]: Type: ${KeyRuleType} (${this.lookupKeyUsageRuleType(KeyRuleType)}), Data: ${this.parseKeyRule(KeyRuleType,KeyRuleData)}\n`;
                    }
                    break;
                case 0xFF: // License verification data
                    const Algorithm = this.readUint8();
                    const KeyIDLength = this.readUint8();
                    const KeyID = this.readString(KeyIDLength);
                    const SignatureLength = this.readUint16();
                    const Signature = this.readString(SignatureLength);
                    res+=` Algorithm: ${Algorithm} (${this.lookupAlgorithm(Algorithm)}), Key ID: ${this.AsciiOrBase64(KeyID)}, Signature: ${this.AsciiOrBase64(Signature)}`;
                    break;

                default:
                    res+=`Reserved Unit Type: ${ident_type}  (see ITU-T J.1041 table 8-1)\n`;    
                    this.skip(ident_length);
                    break;
            }
        }
        return res;
    }
}
