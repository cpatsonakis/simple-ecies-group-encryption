'use strict';

const common = require('../common')
const mycrypto = require('../lib/crypto')

module.exports.encrypt = function (message, ...receiverECDHPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECDHPublicKeys.length === 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    const { symmetricEncryptionKey, macKey, iv } = common.generateOuterSymmetricEncryptionParams()
    const multiRecipientECIESBuffer = common.senderMultiRecipientECIESEncrypt(
        Buffer.concat([symmetricEncryptionKey, macKey], symmetricEncryptionKey.length + macKey.length),
        ...receiverECDHPublicKeys)


    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        Buffer.concat(
            [ciphertext, iv, multiRecipientECIESBuffer],
            ciphertext.length + iv.length + multiRecipientECIESBuffer.length)
    )

    return {
        recvs: multiRecipientECIESBuffer.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}