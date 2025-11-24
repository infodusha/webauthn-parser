import { fromBase64Url } from './utils.js';

const utf8Decoder = new TextDecoder('utf-8');

export type ClientDataType = 'webauthn.create' | 'webauthn.get' | (string & {});

export interface CollectedClientData {
  type: ClientDataType;
  challenge: Uint8Array;
  origin: string;
  crossOrigin?: boolean;
  topOrigin?: string;
  [other_keys_can_be_added_here: string]: unknown;
}

export function parseClient(clientDataJSON: Uint8Array): CollectedClientData {
  const clientData = JSON.parse(utf8Decoder.decode(clientDataJSON));
  return {
    ...clientData,
    challenge: fromBase64Url(clientData.challenge),
  };
}
