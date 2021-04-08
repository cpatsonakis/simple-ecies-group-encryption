'use strict';

const mycrypto = require('../lib/crypto')
const ecies = require('../lib/ecies')

function generateOuterSymmetricEncryptionParams() {
    const entropyBuffer = mycrypto.getRandomBytes(mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize + mycrypto.params.ivSize)
    const symmetricEncryptionKey = entropyBuffer.slice(0, mycrypto.params.symmetricCipherKeySize)
    const macKey = entropyBuffer.slice(mycrypto.params.symmetricCipherKeySize, mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    const iv = entropyBuffer.slice(mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    return {
        symmetricEncryptionKey,
        macKey,
        iv
    }
}

function computeAndSerializeReceiversECIESInstances(symmetricEncryptionKey, ...receiverECPublicKeys) {
    let eciesInstancesArray = []
    receiverECPublicKeys.forEach(function (curReceiverECPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(curReceiverECPublicKey, symmetricEncryptionKey))
    })
    return Buffer.from(JSON.stringify(eciesInstancesArray))
}

module.exports.encrypt = function (message, ...receiverECPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECPublicKeys.length == 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    const { symmetricEncryptionKey, macKey, iv } = generateOuterSymmetricEncryptionParams()
    const receiversECIESInstancesArraySerialized = computeAndSerializeReceiversECIESInstances(
        Buffer.concat([symmetricEncryptionKey, macKey], symmetricEncryptionKey.length + macKey.length),
        ...receiverECPublicKeys)


    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        Buffer.concat(
            [ciphertext, iv, receiversECIESInstancesArraySerialized],
            ciphertext.length + iv.length + receiversECIESInstancesArraySerialized.length))

    return {
        recvs: receiversECIESInstancesArraySerialized.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}