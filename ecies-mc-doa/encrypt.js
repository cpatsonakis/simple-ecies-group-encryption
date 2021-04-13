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

function computeAndSerializeReceiversECIESInstances(senderECKeyPairPEM, symmetricEncryptionKey, ...receiverECPublicKeys) {
    let eciesInstancesArray = []
    receiverECPublicKeys.forEach(function (curReceiverECPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(senderECKeyPairPEM, curReceiverECPublicKey, symmetricEncryptionKey))
    })
    return Buffer.from(JSON.stringify(eciesInstancesArray))
}

function senderMessageWrapAndSerialization(senderPublicKey, message, signature) {
    return JSON.stringify({
        from: senderPublicKey,
        msg: message.toString(mycrypto.encodingFormat),
        sig: signature.toString(mycrypto.encodingFormat)
    });
}

module.exports.encrypt = function (senderECKeyPairPEM, message, ...receiverECPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECPublicKeys.length == 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    const { symmetricEncryptionKey, macKey, iv } = generateOuterSymmetricEncryptionParams()
    const receiversECIESInstancesArraySerialized = computeAndSerializeReceiversECIESInstances(senderECKeyPairPEM,
        Buffer.concat([symmetricEncryptionKey, macKey], symmetricEncryptionKey.length + macKey.length),
        ...receiverECPublicKeys)

    const signature = mycrypto.computeDigitalSignature(senderECKeyPairPEM.privateKey, symmetricEncryptionKey)
    const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECKeyPairPEM.publicKey, message, signature)


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