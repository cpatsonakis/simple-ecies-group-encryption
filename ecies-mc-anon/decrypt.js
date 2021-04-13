'use strict';

const mycrypto = require('../lib/crypto')
const common = require('../common')
const libcommon = require('../lib/common')
const ecies = require('../lib/ecies')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

function isECIESEnvelopeForInputECDHPublicKey(eciesEnvelope, ecdhPublicKey) {
    const envelopeECDHPublicKey = Buffer.from(eciesEnvelope.to_ecdh, mycrypto.encodingFormat)
    return mycrypto.timingSafeEqual(envelopeECDHPublicKey, ecdhPublicKey);
}

function getKeyBufferFromReceiversArray(receiverECDHKeyPair, receiversECIESInstancesString) {
    let receiversECIESInstancesArray = JSON.parse(receiversECIESInstancesString)
    if (receiversECIESInstancesArray.length === 0) {
        throw new Error("Parsed an empty receivers ECIES instances array")
    }
    let myECIESInstanceFound = false;
    let keyBuffer;
    receiversECIESInstancesArray.forEach(function (curReceiverECIESInstance) {
        libcommon.checkEncryptedEnvelopeMandatoryProperties(curReceiverECIESInstance)
        if (isECIESEnvelopeForInputECDHPublicKey(curReceiverECIESInstance, receiverECDHKeyPair.publicKey)) {
            keyBuffer = ecies.decrypt(receiverECDHKeyPair.privateKey, curReceiverECIESInstance)
            myECIESInstanceFound = true;
            return;
        }
    })
    if (!myECIESInstanceFound) {
        throw new Error("Unable to decrypt input envelope with input EC key pair")
    }
    return keyBuffer;
}

function parseKeyBuffer(keyBuffer) {
    if (keyBuffer.length != (mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)) {
        throw new Error("Invalid length of decrypted key buffer")
    }
    const symmetricEncryptionKey = keyBuffer.slice(0, mycrypto.params.symmetricCipherKeySize)
    const macKey = keyBuffer.slice(mycrypto.params.symmetricCipherKeySize)
    return {
        symmetricEncryptionKey,
        macKey
    }
}

module.exports.decrypt = function (receiverECDHKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    common.checkECDHKeyPairMandatoryProperties(receiverECDHKeyPair)

    const keyBuffer = getKeyBufferFromReceiversArray(receiverECDHKeyPair, encEnvelope.recvs)
    const { symmetricEncryptionKey, macKey } = parseKeyBuffer(keyBuffer)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length))
    ) {
        throw new Error("Bad MAC")
    }
    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}