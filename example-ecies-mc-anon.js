const ecies = require('./ecies-mc-anon') //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('./lib/crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');
const totalReceivers = 5;
let receiverECDHPublicKeyArray = [];
let receiverECDHKeyPairArray = [];
let curReceiverECDH;
for(let i = 0; i < totalReceivers; i++) {
    curReceiverECDH = crypto.createECDH(curveName)
    receiverECDHPublicKeyArray.push(curReceiverECDH.generateKeys())
    receiverECDHKeyPairArray.push({
        publicKey: curReceiverECDH.getPublicKey(),
        privateKey: curReceiverECDH.getPrivateKey()
    })
}
let encEnvelope = ecies.encrypt(plainTextMessage, ...receiverECDHPublicKeyArray);
console.log('Encrypted Envelope:')
console.log(encEnvelope)

// Get all the ECDH public keys for which this message was encrypted for
let receiverECDHPubKeyArray = ecies.getReceiverECDHPublicKeyArray(encEnvelope)
// ... each receiver here should attempt to find her corresponding ECDH private key
// ... if no corresponding private key is found, the receiver should throw the message away
let decMessage;
for(let i = 0 ; i < totalReceivers ; i++) {
    decMessage = ecies.decrypt(receiverECDHKeyPairArray[i], encEnvelope)
    assert(Buffer.compare(decMessage, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
}
// Here is the decrypted message!
console.log('Decrypted message is: ' + decMessage);

