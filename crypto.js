var bcrypto        = require('bcrypto');
const Algo         = bcrypto;
const EC           = require('elliptic');
Algo.EC            = EC.ec
Algo.Whirlpool     = Whirlpool     = bcrypto.Whirlpool;
Algo.siphash       = siphash       = bcrypto.siphash;
Algo.keccak256     = keccak256     = bcrypto.Keccak256;
Algo.sha3          = sha3          = bcrypto.SHA3;
Algo.aes           = aes           = bcrypto.aes;
Algo.bcrypt        = bcrypt        = bcrypto.bcrypt;
Algo.BN            = BN            = bcrypto.BN;
Algo.secp256k1     = secp256k1     = bcrypto.secp256k1;
Algo.Poly1305      = Poly1305      = bcrypto.Poly1305;
Algo.scrypt        = scrypt        = bcrypto.scrypt;
Algo.merkle        = merkle        = bcrypto.merkle;
Algo.murmur3       = murmur3       = bcrypto.murmur3;
Algo.blake2b       = blake2b       = bcrypto.BLAKE2b;
Algo.blake2s       = blake2s       = bcrypto.BLAKE2s;
Algo.keccak        = keccak        = bcrypto.Keccak;
Algo.ripemd160     = ripemd160     = bcrypto.RIPEMD160;
Algo.hash160       = hash160       = bcrypto.Hash160;
Algo.pbkdf2        = pbkdf2        = bcrypto.pbkdf2;
Algo.Base64 = Base64 = function(){
    this._keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    this.encode = input => {
        let output = "";
        let chr1;
        let chr2;
        let chr3;
        let enc1;
        let enc2;
        let enc3;
        let enc4;
        let i = 0;
        while (i < input.length) {
            chr1 = input.charCodeAt(i++);
            chr2 = input.charCodeAt(i++);
            chr3 = input.charCodeAt(i++);
            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;
            if (isNaN(chr2)) enc3 = enc4 = 64;
            else if (isNaN(chr3))  enc4 = 64;
            output = output +  this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) + this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
        }
        return output;
    }
    this.encodeIgnoreUtf8 = inputBytes => {
        let output = "";
        let chr1;
        let chr2;
        let chr3;
        let enc1;
        let enc2;
        let enc3;
        let enc4;
        let i = 0;
        while (i < inputBytes.length) {
            chr1 = inputBytes[i++];
            chr2 = inputBytes[i++];
            chr3 = inputBytes[i++];
            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;
            if (isNaN(chr2)) enc3 = enc4 = 64;
            else if (isNaN(chr3)) enc4 = 64;
            output = output +  this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) + this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
        }
        return output;
    }
    this.decode = input => {
        let output = "";
        let chr1;
        let chr2;
        let chr3;
        let enc1;
        let enc2;
        let enc3;
        let enc4;
        let i = 0;
        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
        while (i < input.length) {
            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));
            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;
            output = output + String.fromCharCode(chr1);
            if (enc3 != 64) output = output + String.fromCharCode(chr2);
            if (enc4 != 64) output = output + String.fromCharCode(chr3);
        }
        return this._utf8_decode(output);
    }
    this.decodeToByteArray = input => {
        let output = "";
        let chr1;
        let chr2;
        let chr3;
        let enc1;
        let enc2;
        let enc3;
        let enc4;
        let i = 0;
        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
        while (i < input.length) {
            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));
            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;
            output = output + String.fromCharCode(chr1);
            if (enc3 != 64) output = output + String.fromCharCode(chr2);
            if (enc4 != 64) output = output + String.fromCharCode(chr3);
        }
        return this._out2ByteArray(output);
    }
    this._out2ByteArray = utftext => {
        const byteArray = new Array(utftext.length);
        let i = 0;
        let c = 0;
        while (i < utftext.length) {
            c = utftext.charCodeAt(i);
            byteArray[i] = c;
            i++;
        }
        return byteArray;
    }
    this._utf8_encode = string => {
        string = string.replace(/\r\n/g, "\n");
        let utftext = "";
        for (let n = 0; n < string.length; n++) {
            const c = string.charCodeAt(n);
            if(c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }
        return utftext;
    }
    this._utf8_decode = utftext => {
        let string = "";
        let i = 0;
        let c = 0;
        let c2 = 0;
        let c3 = 0;
        while (i < utftext.length) {
            c = utftext.charCodeAt(i);
            if(c < 128) {
                string += String.fromCharCode(c);
                i++;
            }
            else if ((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i + 1);
                string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i + 1);
                c3 = utftext.charCodeAt(i + 2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
        }
        return string;
    }
}
Algo.varuint       = varuint       =  (function(){
	var MAX_SAFE_INTEGER = 9007199254740991
	function checkUInt53(n){
		if(n < 0 || n > MAX_SAFE_INTEGER || n % 1 !== 0) console.log('value out of range')
	}
	function encode(number, buffer, offset){
		checkUInt53(number)
		if(!buffer) buffer = Buffer.allocUnsafe(encodingLength(number))
		if(!Buffer.isBuffer(buffer)) console.log('buffer must be a Buffer instance')
		if(!offset) offset = 0
		if(number < 0xfd){ // 8 bit
			buffer.writeUInt8(number, offset)
			encode.bytes = 1
		}
		else if(number <= 0xffff){ 	// 16 bit
			buffer.writeUInt8(0xfd, offset)
			buffer.writeUInt16LE(number, offset + 1)
			encode.bytes = 3
		}
		else if (number <= 0xffffffff){  // 32 bit
			buffer.writeUInt8(0xfe, offset)
			buffer.writeUInt32LE(number, offset + 1)
			encode.bytes = 5
		}
		else{	// 64 bit
			buffer.writeUInt8(0xff, offset)
			buffer.writeUInt32LE(number >>> 0, offset + 1)
			buffer.writeUInt32LE((number / 0x100000000) | 0, offset + 5)
			encode.bytes = 9
		}
		return buffer
	}
	function decode(buffer, offset){
		if(!Buffer.isBuffer(buffer)) console.log('buffer must be a Buffer instance')
		if(!offset) offset = 0
		var first = buffer.readUInt8(offset)
		if(first < 0xfd){ // 8 bit
			decode.bytes = 1
			return first
		}	// 16 bit
		else if(first === 0xfd){
			decode.bytes = 3
			return buffer.readUInt16LE(offset + 1)
		}
		else if(first === 0xfe){ // 32 bit
			decode.bytes = 5
			return buffer.readUInt32LE(offset + 1)
		}
		else{ // 64 bit
			decode.bytes = 9
			var lo = buffer.readUInt32LE(offset + 1)
			var hi = buffer.readUInt32LE(offset + 5)
			var number = hi * 0x0100000000 + lo
			checkUInt53(number)
			return number
		}
	}
	function encodingLength(number){
		checkUInt53(number)
		return (number < 0xfd ? 1 : number <= 0xffff ? 3 : number <= 0xffffffff ? 5 : 9)
	}
	return {
		encode: encode,
		decode: decode,
		encodingLength: encodingLength
	}
})()
Algo.basex         = basex = function(ALPHABET){
	var ALPHABET_MAP = {}
	var BASE         = ALPHABET.length
	var LEADER       = ALPHABET.charAt(0)
	for(var z = 0; z < ALPHABET.length; z++){
		var x = ALPHABET.charAt(z)
		if (ALPHABET_MAP[x] !== undefined) throw new TypeError(x + ' is ambiguous')
		ALPHABET_MAP[x] = z
	}
	function encode(source){
		if(source.length === 0) return ''
		var digits = [0]
		for(var i = 0; i < source.length; ++i){
			for(var j = 0, carry = source[i]; j < digits.length; ++j){
				carry    += digits[j] << 8
				digits[j] = carry % BASE
				carry     = (carry / BASE) | 0
			}
			while(carry > 0){
				digits.push(carry % BASE)
				carry = (carry / BASE) | 0
			}
		}
		var string = ''
		for(var k = 0; source[k] === 0 && k < source.length - 1; ++k) string += LEADER
		for(var q = digits.length - 1; q >= 0; --q) string += ALPHABET[digits[q]]
		return string
	}
	function decodeUnsafe(string){
		if(typeof string !== 'string') throw new TypeError('Expected String')
		if(string.length === 0) return Buffer.allocUnsafe(0)
		var bytes = [0]
		for(var i = 0; i < string.length; i++){
			var value = ALPHABET_MAP[string[i]]
			if(value === undefined) return
			for(var j = 0, carry = value; j < bytes.length; ++j){
				carry += bytes[j] * BASE
				bytes[j] = carry & 0xff
				carry >>= 8
			}
			while(carry > 0){
				bytes.push(carry & 0xff)
				carry >>= 8
			}
		}
		for(var k = 0; string[k] === LEADER && k < string.length - 1; ++k) bytes.push(0)
		return Buffer.from(bytes.reverse())
	}
	function decode(string){
		var buffer = decodeUnsafe(string)
		if(buffer) return buffer
		throw new Error('Non-base' + BASE + ' character')
	}
	return {encode: encode, decodeUnsafe: decodeUnsafe, decode: decode}
}
Algo.bip66         = {
	check: function(buffer){
		if(buffer.length < 8) return false
		if(buffer.length > 72) return false
		if(buffer[0] !== 0x30) return false
		if(buffer[1] !== buffer.length - 2) return false
		if(buffer[2] !== 0x02) return false
		var lenR = buffer[3]
		if(lenR === 0) return false
		if(5 + lenR >= buffer.length) return false
		if(buffer[4 + lenR] !== 0x02) return false
		var lenS = buffer[5 + lenR]
		if(lenS === 0) return false
		if((6 + lenR + lenS) !== buffer.length) return false
		if(buffer[4] & 0x80) return false
		if(lenR > 1 && (buffer[4] === 0x00) && !(buffer[5] & 0x80)) return false
		if(buffer[lenR + 6] & 0x80) return false
		if(lenS > 1 && (buffer[lenR + 6] === 0x00) && !(buffer[lenR + 7] & 0x80)) return false
		return true
	},
	decode: function(buffer){
		if(buffer.length < 8) throw new Error('DER длина последовательности слишком короткая')
		if(buffer.length > 72) throw new Error('DER длина последовательности слишком велика')
		if(buffer[0] !== 0x30) throw new Error('Ожидали DER последовательность')
		if(buffer[1] !== buffer.length - 2) throw new Error('DER длина последовательности недействительна')
		if(buffer[2] !== 0x02) throw new Error('Ожидали DER integer')
		var lenR = buffer[3]
		if(lenR === 0) throw new Error('R длина == 0')
		if(5 + lenR >= buffer.length) throw new Error('R слишком длинное')
		if(buffer[4 + lenR] !== 0x02) throw new Error('Ожидали DER integer (2)')
		var lenS = buffer[5 + lenR]
		if(lenS === 0) throw new Error('S длина == 0')
		if((6 + lenR + lenS) !== buffer.length) throw new Error('S длина недействительна')
		if(buffer[4] & 0x80) throw new Error('R == отриицательное')
		if(lenR > 1 && (buffer[4] === 0x00) && !(buffer[5] & 0x80)) throw new Error('R значение чрезмерно дополнено')
		if(buffer[lenR + 6] & 0x80) throw new Error('S == отриицательное')
		if(lenS > 1 && (buffer[lenR + 6] === 0x00) && !(buffer[lenR + 7] & 0x80)) throw new Error('S значение чрезмерно дополнено')
		return {r: buffer.slice(4, 4 + lenR), s: buffer.slice(6 + lenR)} 		// non-BIP66 - extract R, S values
	},
	encode: function(r, s){
		var lenR = r.length
		var lenS = s.length
		if(lenR === 0) throw new Error('R длина == 0')
		if(lenS === 0) throw new Error('S длина == 0')
		if(lenR > 33) throw new Error('R слишком длинное')
		if(lenS > 33) throw new Error('S слишком длинное')
		if(r[0] & 0x80) throw new Error('R == отриицательное')
		if(s[0] & 0x80) throw new Error('S == отриицательное')
		if(lenR > 1 && (r[0] === 0x00) && !(r[1] & 0x80)) throw new Error('R значение чрезмерно дополнено')
		if(lenS > 1 && (s[0] === 0x00) && !(s[1] & 0x80)) throw new Error('S значение чрезмерно дополнено')
		var signature       = Buffer.allocUnsafe(6 + lenR + lenS) 		// 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
		signature[0]        = 0x30
		signature[1]        = signature.length - 2
		signature[2]        = 0x02
		signature[3]        = r.length
		r.copy(signature, 4)
		signature[4 + lenR] = 0x02
		signature[5 + lenR] = s.length
		s.copy(signature, 6 + lenR)
		return signature
	}
}
var ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
var ALPHABET_MAP = {}
for(var z = 0; z < ALPHABET.length; z++){
	var x = ALPHABET.charAt(z)
	if(ALPHABET_MAP[x] !== undefined) throw new TypeError(x + ' is ambiguous')
	ALPHABET_MAP[x] = z
}
function polymodStep(pre){
	var b = pre >> 25
	return ((pre & 0x1FFFFFF) << 5) ^ (-((b >> 0) & 1) & 0x3b6a57b2) ^ (-((b >> 1) & 1) & 0x26508e6d) ^ (-((b >> 2) & 1) & 0x1ea119fa) ^ (-((b >> 3) & 1) & 0x3d4233dd) ^ (-((b >> 4) & 1) & 0x2a1462b3)
}
function prefixChk(prefix){
	var chk = 1
	for(var i = 0; i < prefix.length; ++i) {
		var c = prefix.charCodeAt(i)
		if(c < 33 || c > 126) return 'Invalid prefix (' + prefix + ')'
		chk = polymodStep(chk) ^ (c >> 5)
	}
	chk = polymodStep(chk)
	for(i = 0; i < prefix.length; ++i) {
		var v = prefix.charCodeAt(i)
		chk = polymodStep(chk) ^ (v & 0x1f)
	}
	return chk
}
function __decode(str, LIMIT) {
	LIMIT = LIMIT || 90
	if(str.length < 8) return str + ' too short'
	if(str.length > LIMIT) return 'Exceeds length limit'
	var lowered = str.toLowerCase()
	var uppered = str.toUpperCase()
	if(str !== lowered && str !== uppered) return 'Mixed-case string ' + str
	str = lowered
	var split = str.lastIndexOf('1')
	if(split === -1) return 'No separator character for ' + str
	if(split === 0) return 'Missing prefix for ' + str
	var prefix = str.slice(0, split)
	var wordChars = str.slice(split + 1)
	if(wordChars.length < 6) return 'Data too short'
	var chk = prefixChk(prefix)
	if(typeof chk === 'string') return chk
	var words = []
	for(var i = 0; i < wordChars.length; ++i) {
		var c = wordChars.charAt(i)
		var v = ALPHABET_MAP[c]
		if(v === undefined) return 'Unknown character ' + c
		chk = polymodStep(chk) ^ v
		if(i + 6 >= wordChars.length) continue
		words.push(v)
	}
	if(chk !== 1) return 'Invalid checksum for ' + str
	return {prefix: prefix, words: words}
}
function convert(data, inBits, outBits, pad) {
	var value = 0
	var bits = 0
	var maxV = (1 << outBits) - 1
	var result = []
	for(var i = 0; i < data.length; ++i) {
		value = (value << inBits) | data[i]
		bits += inBits
		while(bits >= outBits) {
			bits -= outBits
			result.push((value >> bits) & maxV)
		}
	}
	if(pad) if(bits > 0) result.push((value << (outBits - bits)) & maxV)
	else{
		if(bits >= inBits) return 'Excess padding'
		if((value << (outBits - bits)) & maxV) return 'Non-zero padding'
	}
	return result
}
Algo.bech32 = {
	decodeUnsafe: function(){
		var res = __decode.apply(null, arguments)
		if(typeof res === 'object') return res
	},
	decode: function (str) {
		var res = __decode.apply(null, arguments)
		if(typeof res === 'object') return res
		throw new Error(res)
	},
	encode: function (prefix, words, LIMIT){
		LIMIT = LIMIT || 90
		if((prefix.length + 7 + words.length) > LIMIT) throw new TypeError('Exceeds length limit')
		prefix = _.toLower(prefix)
		var chk = prefixChk(prefix)
		if(typeof chk === 'string') throw new Error(chk)
		var result = prefix + '1'
		for(var i = 0; i < words.length; ++i) {
			var x = words[i]
			if((x >> 5) !== 0) throw new Error('Non 5-bit word')
			chk = polymodStep(chk) ^ x
			result += ALPHABET.charAt(x)
		}
		for(i = 0; i < 6; ++i) chk = polymodStep(chk)
		chk ^= 1
		for(i = 0; i < 6; ++i) {
			var v = (chk >> ((5 - i) * 5)) & 0x1f
			result += ALPHABET.charAt(v)
		}
		return result
	},
	toWordsUnsafe: function (bytes){
		var res = convert(bytes, 8, 5, true)
		if(Array.isArray(res)) return res
	},
	toWords: function(bytes){
		var res = convert(bytes, 8, 5, true)
		if(Array.isArray(res)) return res
		throw new Error(res)
	},
	fromWordsUnsafe: function(words){
		var res = convert(words, 5, 8, false)
		if(Array.isArray(res)) return res
	},
	fromWords: function(words){
		var res = convert(words, 5, 8, false)
		if(Array.isArray(res)) return res
		throw new Error(res)
	}
}
Algo.bs58check     = bs58check     = function(){
	function encode(payload){
    payload = getBuffer(payload)
		var checksum = Algo.Hash256.digest(payload)
		return base58.encode(Buffer.concat([payload, checksum], payload.length + 4))
	}
	function decodeRaw(buffer){
		var payload     = buffer.slice(0, -4)
		var checksum    = buffer.slice(-4)
		var newChecksum = hash256(payload)
		if(checksum[0] ^ newChecksum[0] | checksum[1] ^ newChecksum[1] | checksum[2] ^ newChecksum[2] | checksum[3] ^ newChecksum[3]) return
		return payload
	}
	function decodeUnsafe(string){
		var buffer = base58.decodeUnsafe(string)
		if(!buffer) return
		return decodeRaw(buffer)
	}
	function decode(string){
    console.log(string)
		var payload = decodeRaw(base58.decode(string));
      console.log(payload)
		if(!payload) throw new Error('Invalid checksum')

		return payload
	}
	return {encode: encode, decode: decode, decodeUnsafe: decodeUnsafe}
}()
Algo.wif       = wif = function(){
	function decodeRaw(buffer, version){
		if(version !== undefined && buffer[0] !== version) throw new Error('Invalid network version')
		if(buffer.length === 33) return {version: buffer[0], privateKey: buffer.slice(1, 33), compressed: false}
		if(buffer.length !== 34) throw new Error('Invalid WIF length')
		if(buffer[33] !== 0x01) throw new Error('Invalid compression flag')
		return {version: buffer[0], privateKey: buffer.slice(1, 33), compressed: true}
	}
	function encodeRaw(version, privateKey, compressed){
		var result = Buffer.allocUnsafe(compressed ? 34 : 33)
		result.writeUInt8(version, 0)
		privateKey.copy(result, 1)
		if(compressed) result[33] = 0x01
		return result
	}
	function decode(string, version){
		return decodeRaw(bs58check.decode(string), version)
	}
	function encode(version, privateKey, compressed){
		if(typeof version === 'number') return bs58check.encode(encodeRaw(version, privateKey, compressed))
	}
	return {decode: decode,	decodeRaw: decodeRaw,	encode: encode, encodeRaw: encodeRaw}
}();
Algo.getBuffer = getBuffer = function getBuffer(buffer){
	if(typeof buffer == 'string') buffer = Buffer.from(buffer, 'hex');
	return buffer;
}
Algo.isHex = isHex = function(value, length){
	if(typeof(value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) return false;
	if(length && value.length !== 2 + 2 * length) { return false; }
	return true;
}
Algo.toHex  = toHex = function(arrayOfBytes){
   var hex = '';
   for(var i = 0; i < arrayOfBytes.length; i++) hex += numberToHex(arrayOfBytes[i]);
   return hex;
}
Algo.numberToHex  = numberToHex = function(number){
	var hex = Math.round(number).toString(16);
	if(hex.length === 1)	hex = '0' + hex;
	return hex;
}
Algo.toUtf8 = toUtf8 = function(hex){
  hex = hex.replace(/^0x/, '');
  return Buffer.from(hex, 'hex').toString('utf8');
}
Algo.byteArray2hexStr  = byteArray2hexStr = function(byteArray){
  let str = '';
  for(let i = 0; i < (byteArray.length); i++) str += byte2hexStr(byteArray[i]);
  return str;
}
Algo.hexStr2byteArray  = hexStr2byteArray = function(str, strict = false){
    if(typeof str !== 'string') return str
    let len = str.length;
    if(strict){
        if(len % 2){
            str = `0${str}`;
            len++;
        }
    }
    const byteArray = Array();
    let d = 0;
    let j = 0;
    let k = 0;
    for(let i = 0; i < len; i++){
        const c = str.charAt(i);
        if(isHexChar(c)){
            d <<= 4;
            d += hexChar2byte(c);
            j++;
            if(0 === (j % 2)){
                byteArray[k++] = d;
                d = 0;
            }
        }
        else throw new Error('The passed hex char is not a valid hex string')
    }
    return byteArray;
}
function add(x, y, base) {
  var z = [];
  var n = Math.max(x.length, y.length);
  var carry = 0;
  var i = 0;
  while (i < n || carry) {
    var xi = i < x.length ? x[i] : 0;
    var yi = i < y.length ? y[i] : 0;
    var zi = carry + xi + yi;
    z.push(zi % base);
    carry = Math.floor(zi / base);
    i++;
  }
  return z;
}
function multiplyByNumber(num, x, base) {
  if (num < 0) return null;
  if (num == 0) return [];
  var result = [];
  var power = x;
  while (true) {
    if (num & 1)  result = add(result, power, base);
    num = num >> 1;
    if (num === 0) break;
    power = add(power, power, base);
  }
  return result;
}
function parseToDigitsArray(str, base) {
  var digits = str.split('');
  var ary = [];
  for (var i = digits.length - 1; i >= 0; i--) {
    var n = parseInt(digits[i], base);
    if (isNaN(n)) return null;
    ary.push(n);
  }
  return ary;
}
function convertBase(str, fromBase, toBase) {
  var digits = parseToDigitsArray(str, fromBase);
  if (digits === null) return null;
  var outArray = [];
  var power = [1];
  for (var i = 0; i < digits.length; i++) {
    if(digits[i]) outArray = add(outArray, multiplyByNumber(digits[i], power, toBase), toBase);
    power = multiplyByNumber(fromBase, power, toBase);
  }
  var out = '';
  for (var i = outArray.length - 1; i >= 0; i--)   out += outArray[i].toString(toBase);
  if (out === '') out = '0';
  return out;
}
Algo.decToHex = decToHex = function(decStr, opts){
  var hidePrefix = opts && opts.prefix === false;
  var hex        = convertBase(decStr, 10, 16);
  return hex ? (hidePrefix ? hex : '0x' + hex) : null;
}
Algo.hexToDec = hexToDec = function(hexStr){
  if (hexStr.substring(0, 2) === '0x') hexStr = hexStr.substring(2);
  hexStr = hexStr.toLowerCase();
  return convertBase(hexStr, 16, 10);
}
Algo.isHexChar = isHexChar = function(c){
    if((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) return 1;
    return 0;
}
Algo.byte2hexStr = byte2hexStr = function(byte){
    if(typeof byte !== 'number') throw new Error('Input must be a number');
    if(byte < 0 || byte > 255) throw new Error('Input must be a byte');
    const hexByteMap = '0123456789ABCDEF';
    let str = '';
    str    += hexByteMap.charAt(byte >> 4);
    str    += hexByteMap.charAt(byte & 0x0f);
    return str;
}
Algo.hexChar2byte = hexChar2byte = function(c){
    let d;
    if (c >= 'A' && c <= 'F')  d = c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
    else if (c >= 'a' && c <= 'f') d = c.charCodeAt(0) - 'a'.charCodeAt(0) + 10;
    else if (c >= '0' && c <= '9') d = c.charCodeAt(0) - '0'.charCodeAt(0);
    if (typeof d === 'number')  return d;
    else throw new Error('The passed hex char is not a valid hex char');
}
Algo.bytesToString = bytesToString = function(arr){
    if(typeof arr === 'string') return arr;
    let str = '';
    for(let i = 0; i < arr.length; i++){
        const one = arr[i].toString(2);
        const v   = one.match(/^1+?(?=0)/);
        if(v && one.length === 8){
            const bytesLength = v[0].length;
            let store = arr[i].toString(2).slice(7 - bytesLength);
            for(let st = 1; st < bytesLength; st++) store += arr[st + i].toString(2).slice(2);
            str += String.fromCharCode(parseInt(store, 2));
            i   += bytesLength - 1;
        }
        else str += String.fromCharCode(arr[i]);
    }
    return str;
}
Algo.hash256   = hash256 = function(buffer){
	return Algo.Hash256.digest(Algo.Hash256.digest(buffer))
}
Algo.base58 = base58 = function base58(){
	var ALPHABETbase58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	return basex(ALPHABETbase58);
}()

const ADDRESS_SIZE            = 34;
const ADDRESS_PREFIX          = "41";
const ADDRESS_PREFIX_BYTE     = 0x41;
const ADDRESS_PREFIX_REGEX    = /^(41)/;
const TRX_MESSAGE_HEADER = '\x19TRON Signed Message:\n32';
// it should be: '\x15TRON Signed Message:\n32';
const ETH_MESSAGE_HEADER = '\x19Ethereum Signed Message:\n32';

const TRON_BIP39_PATH_PREFIX  = "m/44'/195'";
const TRON_BIP39_PATH_INDEX_0 = TRON_BIP39_PATH_PREFIX + "/0'/0/0";

Algo.isValidPrivate = isValidPrivate = function (privateKey){
	privateKey = Algo.getBuffer(privateKey);
	return Algo.secp256k1.privateKeyVerify(privateKey);
}
Algo.isValidPublic = isValidPublic = function (publicKey){
	if(publicKey.length === 64) return Algo.secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]));
	return Algo.secp256k1.publicKeyVerify(publicKey);
}
Algo.isAddressValid = isAddressValid = function(base58Str) {
	console.log(base58Str.length)
	if (base58Str.length === 34) base58Str = getBase58CheckAddress(base58Str)
		console.log(base58Str)
	if (base58Str.length === 42) base58Str = addressToHex(base58Str)
  if(typeof (base58Str) !== 'string') return false;

  if(base58Str.length !== ADDRESS_SIZE) return false;
  let address = Algo.bs58check.decode(base58Str);
  if(address.length !== 25) return false;
  if(address[0] !== ADDRESS_PREFIX_BYTE) return false;
  const checkSum = address.slice(21);
  address        = address.slice(0, 21);

  const hash0 = Algo.Hash256.digest(address);
  const hash1 = Algo.Hash256.digest(hash0);
  const checkSum1 = hash1.slice(0, 4);
	console.log(checkSum1)
  if(checkSum[0] == checkSum1[0] && checkSum[1] == checkSum1[1] && checkSum[2] == checkSum1[2] && checkSum[3] == checkSum1[3]) return true
  return false;
}
function getBase58CheckAddress(addressBytes) {
		addressBytes = Algo.hexStr2byteArray(addressToHex(addressBytes));
    const hash0 = Algo.Hash256.digest(addressBytes);
    const hash1 = Algo.Hash256.digest(hash0);
    let checkSum = hash1.slice(0, 4);

    checkSum = addressBytes.concat(checkSum);
    return Algo.bs58check.encode(checkSum);
}

function decode58Check(addressStr) {
    const decodeCheck = Algo.bs58check.decode(addressStr);
    if (decodeCheck.length <= 4) return false;
    const decodeData = decodeCheck.slice(0, decodeCheck.length - 4);
    const hash0 = Algo.Hash256.digest(decodeData);
    const hash1 = Algo.Hash256.digest(hash0);
    if(hash1[0] === decodeCheck[decodeData.length] && hash1[1] === decodeCheck[decodeData.length + 1] && hash1[2] === decodeCheck[decodeData.length + 2] && hash1[3] === decodeCheck[decodeData.length + 3]) return decodeData;
    return false;
}
function privateToPublic(privateKey){
	privateKey = Algo.getBuffer(privateKey);
	return Algo.secp256k1.publicKeyCreate(privateKey, false).slice(1); 	// skip the type flag and use the X, Y points
};
function importPublic(publicKey) {
	publicKey = Algo.getBuffer(publicKey);
	if(publicKey.length !== 64) publicKey = Algo.secp256k1.publicKeyConvert(publicKey, false).slice(1);
	return publicKey;
};
function ecsign(msgHash, privateKey){
	var sig = Algo.secp256k1.sign(msgHash, privateKey);
	var ret = {};
	ret.r   = sig.signature.slice(0, 32);
	ret.s   = sig.signature.slice(32, 64);
	ret.v   = sig.recovery + 27;
	return ret;
}
function hashPersonalMessage(message) {
	var prefix = Algo.toBuffer(TRX_MESSAGE_HEADER + message.length.toString());
	return Algo.Keccak256.digest(Buffer.concat([prefix, message]));
}
function ecrecover(msgHash, v, r, s){
	var signature = Buffer.concat([setLength(r, 32), setLength(s, 32)], 64);
	var recovery = v - 27;
	if(recovery !== 0 && recovery !== 1) throw new Error('Invalid signature v value');
	var senderPubKey = Algo.secp256k1.recover(msgHash, signature, recovery);
	return Algo.secp256k1.publicKeyConvert(senderPubKey, false).slice(1);
};
function toRpcSig(v, r, s){
	if(v !== 27 && v !== 28) throw new Error('Invalid recovery id');
	return Algo.bufferToHex(Buffer.concat([Algo.setLengthLeft(r, 32), Algo.setLengthLeft(s, 32), Algo.toBuffer(v - 27)]));
}
Algo.fromRpcSig = fromRpcSig = function(sig){
	sig = Algo.getBuffer(sig);
	if(sig.length !== 65) throw new Error('Invalid signature length'); // NOTE: with potential introduction of chainId this might need to be updated
	var v = sig[64];
	if(v < 27) v += 27; 	// support both versions of `eth_sign` responses
	return {v: v,	r: sig.slice(0, 32), s: sig.slice(32, 64)};
};

function base64DecodeFromString(string64){
    return new Algo.Base64().decodeToByteArray(string64);
}
function base64EncodeToString(bytes){
    return new Algo.Base64().encodeIgnoreUtf8(bytes);
}
//console.log(Algo)
function computeAddress(pubBytes){
		pubBytes = Algo.hexStr2byteArray(pubBytes)
    if (pubBytes.length === 65) pubBytes = pubBytes.slice(1);
    const hash = Algo.keccak.digest(Buffer.from(pubBytes)).toString().substring(2);
		console.log(hash)
		const addressHex = ADDRESS_PREFIX + hash.substring(24);
//    return Algo.hexStr2byteArray(addressHex);
		return addressHex
}
function passwordToAddress(password) {
    const com_priKeyBytes  = Algo.base64DecodeFromString(password);
    const com_addressBytes = Algo.getAddressFromPriKey(com_priKeyBytes);
    return Algo.bs58check.encode(com_addressBytes);
}
function getRowBytesFromTransactionBase64(base64Data) {
    const bytesDecode = base64DecodeFromString(base64Data);
    const transaction = proto.protocol.Transaction.deserializeBinary(bytesDecode);
    const raw = transaction.getRawData();
    return raw.serializeBinary();
}
function signBytes(privateKey, contents) {
    if(typeof privateKey === 'string') privateKey = Algo.hexStr2byteArray(privateKey);
    const hashBytes = Algo.Hash256.digest(contents);
    const signBytes = ECKeySign(hashBytes, privateKey);
    return signBytes;
}
function ECKeySign(hashBytes, priKeyBytes){
    const key       = new Algo.EC('secp256k1').keyFromPrivate(priKeyBytes, 'bytes');
    const signature = key.sign(hashBytes);
    const r         = signature.r;
    const s         = signature.s;
    const id        = signature.recoveryParam;
    let rHex        = r.toString('hex');
    while (rHex.length < 64) rHex = `0${rHex}`;
    let sHex = s.toString('hex');
    while (sHex.length < 64) sHex = `0${sHex}`;
    const idHex     = Algo.byte2hexStr(id);
    const signHex   = rHex + sHex + idHex;
    return signHex;
}
function signTransaction(priKeyBytes, transaction){
  if(typeof priKeyBytes === 'string') priKeyBytes = Algo.hexStr2byteArray(priKeyBytes);
  let raw        = transaction.getRawData();
  let rawBytes   = raw.serializeBinary();
  let hashBytes  = Algo.Hash256.digest(rawBytes);
  let signBytes  = ECKeySign(hashBytes, priKeyBytes);
  let uint8Array = new Uint8Array(signBytes);
  let count      = raw.getContractList().length;
  for(let i = 0; i < count; i++) transaction.addSignature(uint8Array);
  return {
		transaction,
		hex: Algo.byteArray2hexStr(transaction.serializeBinary())
	}
}
Algo.signTransaction = function(priKeyBytes, transaction){
    if(typeof priKeyBytes === 'string')  priKeyBytes = Algo.hexStr2byteArray(priKeyBytes);
    const txID      = transaction.txID;
    const signature = ECKeySign(Algo.hexStr2byteArray(txID), priKeyBytes);
    if(Array.isArray(transaction.signature)) if (!transaction.signature.includes(signature)) transaction.signature.push(signature);
    else transaction.signature = [signature];
    return transaction;
}
Algo.privateToAddress = privateToAddress = function(pubKey, sanitize){
	if(typeof pubKey === 'string') pubKey = Algo.hexStr2byteArray(pubKey);
	if(pubKey.length === 65) pubKey = pubKey.slice(1);
	if(sanitize && pubKey.length !== 64) pubKey = Algo.secp256k1.publicKeyConvert(pubKey, false).slice(1);
	//pubKey = Algo.byteArray2hexStr(pubKey)
// )
	pubKey = Algo.getBuffer(Algo.byteArray2hexStr(pubKey));
	console.log(addressFromHex(Buffer.from(Algo.keccak.digest(pubKey)).toString('hex').slice(-20)))
	return ADDRESS_PREFIX + Algo.keccak.digest(pubKey).slice(-20);
}
Algo.getPubKeyFromPriKey = getPubKeyFromPriKey = function(priKeyBytes){
	  if(typeof priKeyBytes === 'string')  priKeyBytes = Algo.hexStr2byteArray(priKeyBytes);
    const ec     = new Algo.EC('secp256k1');
    const key    = ec.keyFromPrivate(priKeyBytes, 'bytes');
    const pubkey = key.getPublic();
    const x      = pubkey.x;
    const y      = pubkey.y;
    let xHex     = x.toString('hex');
    while (xHex.length < 64)   xHex = `0${xHex}`;
    let yHex     = y.toString('hex');
    while (yHex.length < 64)   yHex = `0${yHex}`;
    const pubkeyHex = `04${xHex}${yHex}`;
  //  const pubkeyBytes = Algo.hexStr2byteArray(pubkeyHex);
    return pubkeyHex;
}
Algo.pkToAddress = pkToAddress = function(pubKey, sanitize) {
		pubKey = Algo.getBuffer(pubKey);
		if(sanitize && pubKey.length !== 64) pubKey = Algo.secp256k1.publicKeyConvert(pubKey, false).slice(1);
		var hash = Algo.keccak.digest(pubKey).slice(-20);
		return Algo.addressFromHex(ADDRESS_PREFIX + hash.toString('hex').toLowerCase());
}
Algo.getAddressFromPublic = getAddressFromPublic = function(pubBytes){
	 if(typeof pubBytes === 'string')  pubBytes = Algo.hexStr2byteArray(pubBytes);
   return pkToAddress(pubBytes);
}
Algo.genPriKey = function(){
   const ec      = Algo.EC('secp256k1');
   const key     = ec.genKeyPair();
   const priKey  = key.getPrivate();
   let priKeyHex = priKey.toString('hex');
   while (priKeyHex.length < 64) priKeyHex = `0${priKeyHex}`;
   return Algo.hexStr2byteArray(priKeyHex);
}
Algo.addressToHex = addressToHex = function(address){
	if (Algo.isHex(address)) return address.toLowerCase().replace(/^0x/, ADDRESS_PREFIX);
	return Algo.byteArray2hexStr(Algo.bs58check.decode(address)).toLowerCase();
}
Algo.addressFromHex = addressFromHex = function(address){
  return Algo.bs58check.encode(address)
}
module.exports = Algo
