import { convertCOSEtoPKCS } from './cose.js';
import { toHex } from './utils.js';

export interface AuthenticatorDataResult {
  /** SHA-256 hash of the RP ID the credential is scoped to. */
  rpIdHash: Uint8Array;
  flags: AuthDataFlags;
  signCount: number;
  attestedCredentialData?: AttestedCredentialData;
}

export interface AuthDataFlags {
  userPresent: boolean;
  userVerified: boolean;
  backupEligibility: boolean;
  backupState: boolean;
  attestedData: boolean;
  extensionData: boolean;
}

export interface AttestedCredentialData {
  aaguid: string;
  credentialId: Uint8Array;
  publicKey: Uint8Array;
}

export function parseAuthenticatorData(
  authenticatorData: Uint8Array,
): AuthenticatorDataResult {
  // https://w3c.github.io/webauthn/#sctn-authenticator-data

  const flags = extractFlags(authenticatorData);

  return {
    rpIdHash: extractRpIdHash(authenticatorData),
    flags,
    signCount: extractSignCount(authenticatorData),
    ...(flags.attestedData
      ? { attestedCredentialData: extractAttested(authenticatorData) }
      : {}),
  };
}

function extractRpIdHash(data: Uint8Array) {
  return data.slice(0, 0x20);
}

function extractFlags(data: Uint8Array): AuthDataFlags {
  const flags = new DataView(data.buffer.slice(0x20, 0x21)).getUint8(0);

  function extractFlag(bit: number) {
    return Boolean(flags & (2 ** bit));
  }

  return {
    userPresent: extractFlag(0),
    // reserved: extractFlag(1),
    userVerified: extractFlag(2),
    backupEligibility: extractFlag(3),
    backupState: extractFlag(4),
    // reserved: extractFlag(5),
    attestedData: extractFlag(6),
    extensionData: extractFlag(7),
  };
}

function extractSignCount(data: Uint8Array) {
  return new DataView(data.buffer.slice(0x21, 0x25)).getUint32(0, false);
}

function extractAttested(data: Uint8Array): AttestedCredentialData {
  const credentialId = extractCredentialId(data);

  return {
    aaguid: extractAaguid(data),
    credentialId,
    publicKey: extractPublicKey(data, credentialId.byteLength),
  };
}

function extractAaguid(data: Uint8Array) {
  const hex = toHex(data.slice(0x25, 0x35));

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(
    12,
    16,
  )}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function extractCredentialId(data: Uint8Array) {
  const length = new DataView(data.buffer.slice(0x35, 0x37)).getUint16(
    0,
    false,
  );
  return new Uint8Array(data.buffer.slice(0x37, 0x37 + length));
}

function extractPublicKey(data: Uint8Array, credentialIdLength: number) {
  return convertCOSEtoPKCS(
    new Uint8Array(data.buffer.slice(0x37 + credentialIdLength)),
  );
}
