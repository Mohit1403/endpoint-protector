const crypto = require('crypto');

class CryptoUtils {
    static getSupportedAlgorithms() {
    return {
        // Modern AES algorithms
        'aes-128-cbc': { keyLength: 16, ivLength: 16, type: 'block' },
        'aes-192-cbc': { keyLength: 24, ivLength: 16, type: 'block' },
        'aes-256-cbc': { keyLength: 32, ivLength: 16, type: 'block' },
        'aes-128-gcm': { keyLength: 16, ivLength: 12, type: 'block', authenticated: true },
        'aes-192-gcm': { keyLength: 24, ivLength: 12, type: 'block', authenticated: true },
        'aes-256-gcm': { keyLength: 32, ivLength: 12, type: 'block', authenticated: true },
        'aes-128-ctr': { keyLength: 16, ivLength: 16, type: 'stream' },
        'aes-192-ctr': { keyLength: 24, ivLength: 16, type: 'stream' },
        'aes-256-ctr': { keyLength: 32, ivLength: 16, type: 'stream' },

        // 🔒 Common aliases (so "AES" or "aes" still works - these map to real algorithms)
        'aes': { keyLength: 32, ivLength: 16, type: 'block', realAlgorithm: 'aes-256-cbc' },
        'aes-cbc': { keyLength: 32, ivLength: 16, type: 'block', realAlgorithm: 'aes-256-cbc' },
        'aes256': { keyLength: 32, ivLength: 16, type: 'block', realAlgorithm: 'aes-256-cbc' },

        // Legacy / Educational Ciphers (Working in current Node.js)
        '3des': { keyLength: 24, ivLength: 8, type: 'block', realAlgorithm: 'des-ede3-cbc' },
        'des-ede3-cbc': { keyLength: 24, ivLength: 8, type: 'block' },
        'tripledes': { keyLength: 24, ivLength: 8, type: 'block', realAlgorithm: 'des-ede3-cbc' },
        
        // NOTE: DES, Blowfish, and CAST5 are disabled in newer Node.js versions
        // They are kept for educational purposes but will show appropriate warnings
        'des': { keyLength: 8, ivLength: 8, type: 'block', disabled: true, reason: 'Disabled in Node.js due to security concerns' },
        'des-cbc': { keyLength: 8, ivLength: 8, type: 'block', disabled: true, reason: 'Disabled in Node.js due to security concerns' },
        'blowfish': { keyLength: 32, ivLength: 8, type: 'block', disabled: true, reason: 'Not available in this Node.js version' },
        'blowfish-cbc': { keyLength: 32, ivLength: 8, type: 'block', disabled: true, reason: 'Not available in this Node.js version' },
        'cast5-cbc': { keyLength: 16, ivLength: 8, type: 'block', disabled: true, reason: 'Disabled in Node.js due to security concerns' },

        // Stream / Modern
        'chacha20-poly1305': { keyLength: 32, ivLength: 12, type: 'stream', authenticated: true },
        'chacha20': { keyLength: 32, ivLength: 12, type: 'stream' }
    };
}

    static getAlgorithmInfo(algorithm) {
        const algorithms = this.getSupportedAlgorithms();
        const lower = algorithm.toLowerCase();
        
        // Try direct lookup first
        if (algorithms[lower]) {
            return {
                algorithm: lower,
                ...algorithms[lower],
                description: this.getAlgorithmDescription(lower)
            };
        }
        
        // Try normalized lookup
        if (lower === 'aes') return this.getAlgorithmInfo('aes-256-cbc');
        if (lower === 'des') return this.getAlgorithmInfo('des-cbc');
        if (lower === '3des' || lower === 'tripledes') return this.getAlgorithmInfo('des-ede3-cbc');
        if (lower === 'blowfish') return this.getAlgorithmInfo('blowfish-cbc');
        
        return null;
    }

    static getAlgorithmDescription(algorithm) {
        const descriptions = {
            'aes-128-cbc': 'AES 128-bit CBC mode - Good balance of security and performance',
            'aes-192-cbc': 'AES 192-bit CBC mode - Higher security than AES-128',
            'aes-256-cbc': 'AES 256-bit CBC mode - Maximum security, industry standard',
            'aes-128-gcm': 'AES 128-bit GCM mode - Authenticated encryption with additional data',
            'aes-192-gcm': 'AES 192-bit GCM mode - Authenticated encryption, higher security',
            'aes-256-gcm': 'AES 256-bit GCM mode - Maximum security authenticated encryption',
            'aes-128-ctr': 'AES 128-bit CTR mode - Stream cipher mode, parallelizable',
            'aes-192-ctr': 'AES 192-bit CTR mode - Stream cipher, higher security',
            'aes-256-ctr': 'AES 256-bit CTR mode - Maximum security stream cipher',
            'des': 'DES - ❌ DISABLED: Not available due to security concerns',
            'des-cbc': 'DES CBC mode - ❌ DISABLED: Not available due to security concerns',
            '3des': 'Triple DES (3DES) - Legacy cipher, use with caution',
            'tripledes': 'Triple DES (3DES) - Legacy cipher, use with caution', 
            'des-ede3-cbc': 'Triple DES CBC mode - Legacy cipher with better security than DES',
            'blowfish': 'Blowfish - ❌ DISABLED: Not available in this Node.js version',
            'blowfish-cbc': 'Blowfish CBC mode - ❌ DISABLED: Not available in this Node.js version',
            'cast5-cbc': 'CAST5 CBC mode - ❌ DISABLED: Not available due to security concerns',
            'chacha20-poly1305': 'ChaCha20-Poly1305 - Modern authenticated encryption',
            'chacha20': 'ChaCha20 - Modern stream cipher, alternative to AES'
        };
        return descriptions[algorithm] || 'Cryptographic algorithm';
    }

    // 🔒 Modern encryption
    static encrypt(algorithm, text, key, options = {}) {
        try {
            let algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
            if (!algConfig) {
                // Try to normalize simple names like "AES" → "aes-256-cbc"
                const lower = algorithm.toLowerCase();
                if (lower === 'aes') {
                    algorithm = 'aes-256-cbc';
                    algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
                } else if (lower === '3des' || lower === 'tripledes') {
                    algorithm = '3des';
                    algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
                } else {
                    throw new Error(`Unsupported algorithm: ${algorithm}`);
                }
            }
            
            // Check if algorithm is disabled
            if (algConfig.disabled) {
                throw new Error(`Algorithm '${algorithm}' is not available: ${algConfig.reason}`);
            }
            const keyBuffer = this.prepareKey(key, algConfig.keyLength);
            const iv = options.iv
                ? Buffer.from(options.iv, 'hex')
                : crypto.randomBytes(algConfig.ivLength);

            // Use realAlgorithm if available (for aliases), otherwise use the algorithm
            const actualAlgorithm = algConfig.realAlgorithm || algorithm;
            const cipher = crypto.createCipheriv(actualAlgorithm, keyBuffer, iv);

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const result = {
                encrypted,
                iv: iv.toString('hex'),
                algorithm: algConfig.realAlgorithm || algorithm
            };

            if (algConfig.authenticated && cipher.getAuthTag) {
                result.authTag = cipher.getAuthTag().toString('hex');
            }

            return result;
        } catch (err) {
            throw new Error(`Encryption failed: ${err.message}`);
        }
    }

    // 🔓 Modern decryption
    static decrypt(algorithm, encryptedData, key, options = {}) {
        try {
            let algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
            if (!algConfig) {
                // Try to normalize simple names like "AES" → "aes-256-cbc"
                const lower = algorithm.toLowerCase();
                if (lower === 'aes') {
                    algorithm = 'aes-256-cbc';
                    algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
                } else if (lower === '3des' || lower === 'tripledes') {
                    algorithm = '3des';
                    algConfig = this.getSupportedAlgorithms()[algorithm.toLowerCase()];
                } else {
                    throw new Error(`Unsupported algorithm: ${algorithm}`);
                }
            }
            
            // Check if algorithm is disabled
            if (algConfig.disabled) {
                throw new Error(`Algorithm '${algorithm}' is not available: ${algConfig.reason}`);
            }

            const encryptedText =
                typeof encryptedData === 'object' ? encryptedData.encrypted : encryptedData;
            const ivHex =
                typeof encryptedData === 'object' && encryptedData.iv
                    ? encryptedData.iv
                    : options.iv;
            const iv = Buffer.from(ivHex, 'hex');
            const authTagHex =
                typeof encryptedData === 'object' && encryptedData.authTag
                    ? encryptedData.authTag
                    : options.authTag;

            const keyBuffer = this.prepareKey(key, algConfig.keyLength);
            // Use realAlgorithm if available (for aliases), otherwise use the algorithm
            const actualAlgorithm = algConfig.realAlgorithm || algorithm;
            const decipher = crypto.createDecipheriv(actualAlgorithm, keyBuffer, iv);

            if (algConfig.authenticated && authTagHex) {
                decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
            }

            let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (err) {
            throw new Error(`Decryption failed: ${err.message}`);
        }
    }

    // 🔑 Key normalization helper
    static prepareKey(key, targetLength) {
        const keyBuffer = Buffer.from(key, 'utf8');
        if (keyBuffer.length === targetLength) return keyBuffer;
        if (keyBuffer.length > targetLength) return keyBuffer.slice(0, targetLength);
        const padded = Buffer.alloc(targetLength);
        keyBuffer.copy(padded);
        return padded;
    }

    // ✅ Hashing
    static hash(text, algorithm = 'sha256') {
        try {
            return crypto.createHash(algorithm).update(text, 'utf8').digest('hex');
        } catch (err) {
            throw new Error(`Hashing failed: ${err.message}`);
        }
    }

    // ✅ HMAC
    static hmac(text, key, algorithm = 'sha256') {
        try {
            return crypto.createHmac(algorithm, key).update(text, 'utf8').digest('hex');
        } catch (err) {
            throw new Error(`HMAC generation failed: ${err.message}`);
        }
    }

    // ✅ Encoding/Decoding
    static base64Encode(text) {
        return Buffer.from(text, 'utf8').toString('base64');
    }

    static base64Decode(encoded) {
        return Buffer.from(encoded, 'base64').toString('utf8');
    }

    static hexEncode(text) {
        return Buffer.from(text, 'utf8').toString('hex');
    }

    static hexDecode(hexText) {
        return Buffer.from(hexText, 'hex').toString('utf8');
    }

    static urlEncode(text) {
        return encodeURIComponent(text);
    }

    static urlDecode(text) {
        return decodeURIComponent(text);
    }

    static binaryEncode(text) {
        return text.split('')
            .map(ch => ch.charCodeAt(0).toString(2).padStart(8, '0'))
            .join(' ');
    }

    static binaryDecode(binaryText) {
        return binaryText.split(' ')
            .map(bin => String.fromCharCode(parseInt(bin, 2)))
            .join('');
    }

    // ✅ Random generation
    static generateRandomKey(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    static generateRandomIV(length = 16) {
        return crypto.randomBytes(length).toString('hex');
    }

    // ✅ PBKDF2 key derivation
    static deriveKey(password, salt, iterations = 10000, keyLength = 32, digest = 'sha256') {
        const derived = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest);
        return derived.toString('hex');
    }

    // ✅ Caesar Cipher (educational)
    static caesarCipher(text, shift = 3) {
        return text.replace(/[a-zA-Z]/g, c => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
        });
    }

    static caesarDecipher(text, shift = 3) {
        return this.caesarCipher(text, 26 - shift);
    }

    static rot13(text) {
        return this.caesarCipher(text, 13);
    }

    static atbash(text) {
        return text.replace(/[a-zA-Z]/g, c => {
            if (c <= 'Z') return String.fromCharCode(90 - (c.charCodeAt(0) - 65));
            return String.fromCharCode(122 - (c.charCodeAt(0) - 97));
        });
    }

    // ✅ Signing (RSA or fallback to HMAC)
    static sign(text, privateKey) {
        try {
            const sign = crypto.createSign('RSA-SHA256');
            sign.update(text);
            return sign.sign(privateKey, 'hex');
        } catch {
            return this.hmac(text, privateKey);
        }
    }

    static verify(text, signature, publicKey) {
        try {
            const verify = crypto.createVerify('RSA-SHA256');
            verify.update(text);
            return verify.verify(publicKey, signature, 'hex');
        } catch {
            return this.hmac(text, publicKey) === signature;
        }
    }
}

module.exports = CryptoUtils;