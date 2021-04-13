'use strict';

const libcommon = require('../lib/common')

module.exports.getReceiverECDHPublicKeyArray = function(encEnvelope) {
    if (encEnvelope.recvs === undefined) {
        throw new Error('Mandatory property recvs not found in encrypted envelope')
    }
    let receiversArray = JSON.parse(encEnvelope.recvs)
    if (receiversArray.length === 0) {
        throw new Error('Invalid receiver array in encrypted envelope')
    }
    let receiverECDHPublicKeyArray = [];
    receiversArray.forEach(function(curReceiverECIESInstance) {
        libcommon.checkEncryptedEnvelopeMandatoryProperties(curReceiverECIESInstance)
        let curReceiverECDHPublicKey = libcommon.getDecodedECDHPublicKeyFromEncEnvelope(curReceiverECIESInstance)
        receiverECDHPublicKeyArray.push(curReceiverECDHPublicKey)

    })
    if (receiverECDHPublicKeyArray.length === 0) {
        throw new Error('Unable to parse any of the receivers\' ECIES instances')
    }
    return receiverECDHPublicKeyArray;
}

module.exports.checkECDHKeyPairMandatoryProperties = function(ecdhKeyPairObject) {
    const mandatoryProperties = ["publicKey", "privateKey"];
    mandatoryProperties.forEach((property) => {
        if (typeof ecdhKeyPairObject[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input ECDH key pair object");
        }
    })

}