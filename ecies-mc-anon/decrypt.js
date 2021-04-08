'use strict';

const mycrypto = require('../lib/crypto')
const jscrypto = require('crypto')
const ecies = require('../lib/ecies')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === undefined) {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

function checkECIESEnvelopeMandatoryProperties(eciesEnvelope) {
    const mandatoryProperties = ["to", "r", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof eciesEnvelope[property] === undefined) {
            throw new Error("Mandatory property " + property + " is missing from ECIES encrypted envelope");
        }
    })
}

function isECIESEnvelopeForInputECPublicKey(eciesEnvelope, ecPublicKey) {
    let envelopeECPublicKey = Buffer.from(eciesEnvelope.to, mycrypto.encodingFormat)
    return jscrypto.timingSafeEqual(envelopeECPublicKey, ecPublicKey);
}

function getKeyBufferFromReceiversArray(receiverECKeyPair, receiversBufferArray) {
    let receiversECIESInstancesArray = JSON.parse(receiversBufferArray.toString())
    if (receiversECIESInstancesArray.length === 0) {
        throw new Error("Parsed an empty receivers ECIES instances array")
    }
    let myECIESInstanceFound = false;
    let keyBuffer;
    let senderECPublicKey;
    receiversECIESInstancesArray.forEach(function(curReceiverECIESInstance) {
        checkECIESEnvelopeMandatoryProperties(curReceiverECIESInstance)
        if (isECIESEnvelopeForInputECPublicKey(curReceiverECIESInstance, receiverECKeyPair.publicKey)) {
            keyBuffer= ecies.decrypt(receiverECKeyPair.privateKey, curReceiverECIESInstance)
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

module.exports.decrypt = function(receiverECKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)
    const receiversBufferArray = Buffer.from(encEnvelope.recvs, mycrypto.encodingFormat)

    const keyBuffer = getKeyBufferFromReceiversArray(receiverECKeyPair, receiversBufferArray)
    const { symmetricEncryptionKey, macKey } = parseKeyBuffer(keyBuffer)

    if(!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        Buffer.concat([ciphertext, iv, receiversBufferArray], ciphertext.length + iv.length + receiversBufferArray.length))) {
        throw new Error("Bad MAC")
    }
    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}