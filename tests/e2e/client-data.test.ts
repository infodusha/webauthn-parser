import { expect, test } from '@playwright/test';
import { parseClient } from '../../src/index.js';

test('clientData', async ({ page }) => {
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

  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const clientDataJSON = await page.evaluate(
    async ([challenge]) => {
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions =
        {
          challenge,
          rp: {
            name: 'Test RP',
            id: 'example.tld',
          },
          user: {
            id: new Uint8Array([1, 2, 3, 4]),
            name: 'test@example.com',
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
      const clientDataJSONArrayBuffer = response.clientDataJSON;
      return new Uint8Array(clientDataJSONArrayBuffer);
    },
    [challenge],
  );

  const parsedClientData = parseClient(clientDataJSON);

  expect(parsedClientData.type).toBe('webauthn.create');
  expect(parsedClientData.origin).toBe('https://example.tld');
  expect(parsedClientData.challenge).toEqual(challenge);
});
