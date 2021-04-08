const ecies = require('./ecies-mc-anon') //import the ECIES module
const assert = require('assert').strict;
// The next two lines are required to properly import and initialize the pskcrypto module
$$ = { Buffer };
const pskcrypto = require("./lib/pskcrypto");
// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');
let keyGenerator = pskcrypto.createKeyPairGenerator(); // Object that allows us to generate EC key pairs
const totalReceivers = 5;
let receiversECKeyPairArray = [];
let receiversECPublicKeyArray = [];
for (let i = 0; i < totalReceivers; i++) {
    //Generate an EC key pair for each message receiver
    receiversECKeyPairArray.push(keyGenerator.generateKeyPair())
    receiversECPublicKeyArray.push(receiversECKeyPairArray[i].publicKey)
}

// Encrypt the message. The function returns a JSON object that you can send over any communication
// channel you want (e.g., HTTP, WS).
for (let i = 0; i < totalReceivers; i++) {
    let encEnvelope = ecies.encrypt(plainTextMessage, ...receiversECPublicKeyArray)
    console.log("Encrypted Envelope:")
    console.log(encEnvelope)
    let decMessage = ecies.decrypt(receiversECKeyPairArray[0], encEnvelope)
    assert(Buffer.compare(decMessage, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
    // Here is the decrypted message!
    console.log('Decrypted message is: ' + decMessage);
}