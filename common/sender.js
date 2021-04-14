'use strict';

const mycrypto = require('../lib/crypto')
const ecies = require('../lib/ecies')

module.exports.generateOuterSymmetricEncryptionParams = function () {
    const symmetricEncryptionKey = mycrypto.getRandomBytes(mycrypto.params.symmetricCipherKeySize)
    const macKey = mycrypto.getRandomBytes(mycrypto.params.macKeySize)
    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    return {
        symmetricEncryptionKey,
        macKey,
        iv
    }
}

module.exports.senderMultiRecipientECIESEncrypt = function(message, ...receiverECDHPublicKeyArray) {
    let eciesInstancesArray = []
    receiverECDHPublicKeyArray.forEach(function (curReceiverECDHPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(curReceiverECDHPublicKey, message))
    })
    return Buffer.from(JSON.stringify(eciesInstancesArray))
}