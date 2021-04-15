'use strict';

const mycrypto = require('../lib/crypto')
const common = require('../common')
const libcommon = require('../lib/common')
const crypto = require('crypto')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "ct", "iv", "tag", "from_ecsig", "sig"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

module.exports.decrypt = function(receiverECDHKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    libcommon.checkKeyPairMandatoryProperties(receiverECDHKeyPair)


    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)
    const receiverECIESInstancesBuffer = Buffer.from(encEnvelope.recvs, mycrypto.encodingFormat)

    const keyBuffer = common.receiverMultiRecipientECIESDecrypt(receiverECDHKeyPair, receiverECIESInstancesBuffer)
    const { symmetricEncryptionKey, macKey } = common.parseKeyBuffer(keyBuffer)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        Buffer.concat([ciphertext, iv, receiverECIESInstancesBuffer],
            ciphertext.length + iv.length + receiverECIESInstancesBuffer.length))
    ) {
        throw new Error("Bad MAC")
    }

    const senderECSigVerPublicKey = crypto.createPublicKey({
        key: encEnvelope.from_ecsig,
        format: 'pem',
        type: 'spki'
    })
    if (!mycrypto.verifyDigitalSignature(senderECSigVerPublicKey,
        Buffer.from(encEnvelope.sig, mycrypto.encodingFormat),
        tag)) {
        throw new Error("Bad signature")
    }
    
    return {
        from: senderECSigVerPublicKey,
        message: mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv)
    }
}