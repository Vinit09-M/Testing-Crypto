import { constants, verify } from 'node:crypto';

export function verifyPartnerManifest(publicKey, manifest, signature) {
  return verify('RSA-SHA256', manifest, {
    key: publicKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }, signature);
}
