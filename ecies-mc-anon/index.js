'use strict';

module.exports = {
  encrypt: require('./encrypt').encrypt,
  decrypt: require('./decrypt').decrypt,
  getRecipientECDHPublicKeysFromEncEnvelope: require('../common').getRecipientECDHPublicKeysFromEncEnvelope
}