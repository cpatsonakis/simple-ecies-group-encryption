'use strict';

const mycrypto = require('../lib/crypto')
const common = require('../common')
const libcommon = require('../lib/common')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input group encrypted envelope");
        }
    })
}

module.exports.decrypt = function (receiverECDHKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    libcommon.checkKeyPairMandatoryProperties(receiverECDHKeyPair)
    const receiverECIESInstancesBuffer = Buffer.from(encEnvelope.recvs, mycrypto.encodingFormat)

    const keyBuffer = common.receiverMultiRecipientECIESDecrypt(receiverECDHKeyPair, receiverECIESInstancesBuffer)
    const { symmetricEncryptionKey, macKey } = common.parseKeyBuffer(keyBuffer)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        Buffer.concat([ciphertext, iv, receiverECIESInstancesBuffer],
            ciphertext.length + iv.length + receiverECIESInstancesBuffer.length))
    ) {
        throw new Error("Bad MAC")
    }
    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
}