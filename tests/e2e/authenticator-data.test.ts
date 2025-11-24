import { expect, test } from '@playwright/test';
import { parseAuthenticatorData } from '../../src/index.js';
import { fromBase64Url } from '../../src/utils.js';

test('authenticatorData', async ({ page }) => {
  await page.route('https://example.tld/**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<html><body></body></html>',
    });
  });

  await page.goto('https://example.tld');

  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');

  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });

  const {
    authenticatorData,
    credentialId,
    publicKey: publicKeyArray,
  } = await page.evaluate(async () => {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions =
      {
        challenge,
        rp: {
          name: 'Test RP',
          id: 'example.tld',
        },
        user: {
          id: new Uint8Array([1, 2, 3, 4]),
          name: 'test@example.tld',
          displayName: 'Test User',
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'preferred',
        },
      };

    const credential = (await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    })) as PublicKeyCredential;

    const response = credential.response as AuthenticatorAttestationResponse;
    const authenticatorDataArrayBuffer = response.getAuthenticatorData();

    return {
      authenticatorData: new Uint8Array(authenticatorDataArrayBuffer),
      credentialId: new Uint8Array(credential.rawId),
      publicKey: new Uint8Array(response.getPublicKey() as ArrayBuffer),
    };
  });

  const parsedAuthenticatorData = parseAuthenticatorData(authenticatorData);

  expect(parsedAuthenticatorData.attestedCredentialData?.credentialId).toEqual(
    credentialId,
  );

  const publicKeyFromParser =
    parsedAuthenticatorData.attestedCredentialData?.publicKey;

  const publicKeyFromResponse =
    await extractPublicKeyPointFromDER(publicKeyArray);

  expect(publicKeyFromParser).toEqual(publicKeyFromResponse);

  expect(parsedAuthenticatorData.rpIdHash).toEqual(expectedRpIdHash);

  expect(parsedAuthenticatorData.flags.userPresent).toBe(true);
  expect(parsedAuthenticatorData.flags.userVerified).toBe(true);
  expect(parsedAuthenticatorData.flags.backupEligibility).toBe(false);
  expect(parsedAuthenticatorData.flags.backupState).toBe(false);
  expect(parsedAuthenticatorData.flags.attestedData).toBe(true);
  expect(parsedAuthenticatorData.flags.extensionData).toBe(false);

  expect(parsedAuthenticatorData.signCount).toBe(1);

  expect(parsedAuthenticatorData.attestedCredentialData?.aaguid).toBe(
    '01020304-0506-0708-0102-030405060708',
  );
});

const expectedRpIdHash = await sha256('example.tld');

async function sha256(value: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

async function extractPublicKeyPointFromDER(
  der: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    der.slice().buffer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['verify'],
  );

  const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);

  if (!jwk.x || !jwk.y) {
    throw new Error('Invalid EC public key: missing x or y coordinates');
  }

  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);

  return new Uint8Array([0x04, ...x, ...y]);
}
