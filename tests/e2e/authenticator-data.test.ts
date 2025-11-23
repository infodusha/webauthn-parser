import { test, expect } from "@playwright/test";
import { parseAuthenticatorData } from "../../src/index.js";
import { createPublicKey } from "node:crypto";
import { fromBase64Url } from "../../src/utils.js";

test("authenticatorData", async ({ page }) => {
    await page.route("https://example.tld/**", (route) => {
        route.fulfill({
            status: 200,
            contentType: "text/html",
            body: "<html><body></body></html>",
        });
    });

    await page.goto("https://example.tld");

    const client = await page.context().newCDPSession(page);
    await client.send("WebAuthn.enable");

    await client.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            options: {
                protocol: "ctap2",
                transport: "internal",
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
            },
        }
    );

    await page.evaluate(() => {
        (window as any).__webauthnResult = null;
        (window as any).__webauthnError = null;
        (window as any).__credentialId = null;
        (window as any).__publicKey = null;

        const button = document.createElement("button");
        button.id = "webauthn-button";
        button.textContent = "Create";
        document.body.appendChild(button);

        button.addEventListener("click", async () => {
            try {
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);

                const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions =
                {
                    challenge,
                    rp: {
                        name: "Test RP",
                        id: "example.tld",
                    },
                    user: {
                        id: new Uint8Array([1, 2, 3, 4]),
                        name: "test@example.tld",
                        displayName: "Test User",
                    },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        userVerification: "preferred",
                    },
                };

                const credential = (await navigator.credentials.create({
                    publicKey: publicKeyCredentialCreationOptions,
                })) as PublicKeyCredential;

                const response = credential.response as AuthenticatorAttestationResponse;
                const authenticatorDataArrayBuffer = response.getAuthenticatorData();

                (window as any).__credentialId = Array.from(new Uint8Array(credential.rawId));

                (window as any).__publicKey = Array.from(new Uint8Array(response.getPublicKey()!));

                (window as any).__webauthnResult = Array.from(new Uint8Array(authenticatorDataArrayBuffer));
            } catch (error) {
                (window as any).__webauthnError = String(error);
            }
        });
    });

    await page.click("#webauthn-button");

    await page.waitForFunction(() => (window as any).__webauthnResult !== null || (window as any).__webauthnError !== null);

    const { authenticatorData, credentialId, publicKey: publicKeyArray } = await page.evaluate(() => {
        if ((window as any).__webauthnError) {
            throw new Error((window as any).__webauthnError);
        }
        return {
            authenticatorData: (window as any).__webauthnResult as number[],
            credentialId: (window as any).__credentialId as number[],
            publicKey: (window as any).__publicKey as number[],
        };
    });

    const authenticatorDataUint8 = new Uint8Array(authenticatorData);
    const parsedAuthenticatorData = parseAuthenticatorData(authenticatorDataUint8);

    const expectedCredentialId = new Uint8Array(credentialId);
    expect(parsedAuthenticatorData.attestedCredentialData?.credentialId).toEqual(expectedCredentialId);

    const publicKeyFromResponseDER = new Uint8Array(publicKeyArray);
    const publicKeyFromParser = parsedAuthenticatorData.attestedCredentialData?.publicKey;

    const publicKeyFromResponse = extractPublicKeyPointFromDER(publicKeyFromResponseDER);

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
        '01020304-0506-0708-0102-030405060708'
    );
});


const encoder = new TextEncoder();
const data = encoder.encode("example.tld");
const hashBuffer = await crypto.subtle.digest("SHA-256", data);
const expectedRpIdHash = new Uint8Array(hashBuffer);


function extractPublicKeyPointFromDER(der: Uint8Array): Uint8Array {
    const keyObject = createPublicKey({
        key: Buffer.from(der),
        format: 'der',
        type: 'spki'
    });

    const jwk = keyObject.export({ format: 'jwk' });

    if (!jwk.x || !jwk.y) {
        throw new Error("Invalid EC public key: missing x or y coordinates");
    }


    const x = fromBase64Url(jwk.x);
    const y = fromBase64Url(jwk.y);

    return new Uint8Array([0x04, ...x, ...y]);
}