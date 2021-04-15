'use strict';

const mycrypto = require('../lib/crypto')
const common = require('../common')
const libcommon = require('../lib/common')

module.exports.encrypt = function (senderECSigningKeyPair, message, ...receiverECDHPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECDHPublicKeys.length == 0) {
        throw new Error('Need to specify at least one receiver public key')
    }
    libcommon.checkKeyPairMandatoryProperties(senderECSigningKeyPair)

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

    const signature = mycrypto.computeDigitalSignature(senderECSigningKeyPair.privateKey, tag)

    return {
        recvs: multiRecipientECIESBuffer.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat),
        from_ecsig: senderECSigningKeyPair.publicKey.export({
            type: 'spki',
            format: 'pem'
        }),
        sig: signature.toString(mycrypto.encodingFormat)
    }
}