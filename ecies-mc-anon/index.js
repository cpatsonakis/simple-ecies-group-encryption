'use strict';

module.exports = {
  encrypt: require('./encrypt').encrypt,
  decrypt: require('./decrypt').decrypt,
  getReceiverECDHPublicKeyArray: require('../common').getReceiverECDHPublicKeyArray
}