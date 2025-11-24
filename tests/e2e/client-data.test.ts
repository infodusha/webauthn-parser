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

  await page.evaluate(
    ([challenge]) => {
      (window as any).__webauthnResult = null;
      (window as any).__webauthnError = null;

      const button = document.createElement('button');
      button.id = 'webauthn-button';
      button.textContent = 'Create';
      document.body.appendChild(button);

      button.addEventListener('click', async () => {
        try {
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

          const response =
            credential.response as AuthenticatorAttestationResponse;
          const clientDataJSONArrayBuffer = response.clientDataJSON;
          (window as any).__webauthnResult = Array.from(
            new Uint8Array(clientDataJSONArrayBuffer),
          );
        } catch (error) {
          (window as any).__webauthnError = String(error);
        }
      });
    },
    [challenge],
  );

  await page.click('#webauthn-button');

  await page.waitForFunction(
    () =>
      (window as any).__webauthnResult !== null ||
      (window as any).__webauthnError !== null,
  );

  const clientDataJSON = await page.evaluate(() => {
    if ((window as any).__webauthnError) {
      throw new Error((window as any).__webauthnError);
    }
    return (window as any).__webauthnResult as number[];
  });

  const clientDataJSONUint8 = new Uint8Array(clientDataJSON);
  const parsedClientData = parseClient(clientDataJSONUint8);

  expect(parsedClientData.type).toBe('webauthn.create');
  expect(parsedClientData.origin).toBe('https://example.tld');
  expect(parsedClientData.challenge).toEqual(challenge);
});
