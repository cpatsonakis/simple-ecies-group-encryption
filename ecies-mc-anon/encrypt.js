'use strict';

const mycrypto = require('../lib/crypto')
const ecies = require('../lib/ecies')

function generateOuterSymmetricEncryptionParams() {
    const symmetricEncryptionKey = mycrypto.getRandomBytes(mycrypto.params.symmetricCipherKeySize)
    const macKey = mycrypto.getRandomBytes(mycrypto.params.macKeySize)
    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    return {
        symmetricEncryptionKey,
        macKey,
        iv
    }
}

function computeAndSerializeReceiversECIESInstances(keyBuffer, ...receiverECDHPublicKeys) {
    let eciesInstancesArray = []
    receiverECDHPublicKeys.forEach(function (curReceiverECDHPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(curReceiverECDHPublicKey, keyBuffer))
    })
    return JSON.stringify(eciesInstancesArray)
}

module.exports.encrypt = function (message, ...receiverECDHPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECDHPublicKeys.length === 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    const { symmetricEncryptionKey, macKey, iv } = generateOuterSymmetricEncryptionParams()
    const receiversECIESInstancesArraySerialized = computeAndSerializeReceiversECIESInstances(
        Buffer.concat([symmetricEncryptionKey, macKey], symmetricEncryptionKey.length + macKey.length),
        ...receiverECDHPublicKeys)


    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        Buffer.concat(
            [ciphertext, iv],
            ciphertext.length + iv.length)
    )

    return {
        recvs: receiversECIESInstancesArraySerialized,
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}