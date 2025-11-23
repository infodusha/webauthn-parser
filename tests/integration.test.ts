import { expect, test } from "bun:test";

import { parseAuthenticatorData, parseClient } from "../src";

test("clientData", () => {
  const clientDataJSON =
    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2241514944222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303330222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2f796162506578227d";

  const collectedClientData = parseClient(Uint8Array.fromHex(clientDataJSON));

  expect(collectedClientData.type).toBe("webauthn.create");
  expect(collectedClientData.challenge).toEqual(new Uint8Array([1, 2, 3]));
  expect(collectedClientData.origin).toBe("http://localhost:3030");
});

test("authenticatorData", () => {
  const authenticatorData =
    "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97635d00000000fbfc3007154e4ecc8c0b6e020557d7bd0014f67c2c1aa5c54e243eeeaa4c0de36d9e3205d985a5010203262001215820580b3439a0f5f9b2fcfea1eb89c77561684eb6d78345d8cffc91f997e360c5cf225820adcc13f9d817e09212eae65d57a756e110c8db6cafe5d28ca794dbc36d259ebf";

  const authenticatorDataResult = parseAuthenticatorData(
    Uint8Array.fromHex(authenticatorData)
  );

  expect(authenticatorDataResult.rpIdHash.byteLength).toBe(32);

  expect(authenticatorDataResult.flags.userPresent).toBe(true);
  expect(authenticatorDataResult.flags.userVerified).toBe(true);
  expect(authenticatorDataResult.flags.backupEligibility).toBe(true);
  expect(authenticatorDataResult.flags.backupState).toBe(true);
  expect(authenticatorDataResult.flags.attestedData).toBe(true);
  expect(authenticatorDataResult.flags.extensionData).toBe(false);

  expect(authenticatorDataResult.signCount).toBe(0);

  expect(authenticatorDataResult.attestedCredentialData).toBeDefined();
  expect(authenticatorDataResult.attestedCredentialData?.aaguid).toBe(
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
  );

  expect(
    authenticatorDataResult.attestedCredentialData?.credentialId.byteLength
  ).toBe(20);

  expect(
    authenticatorDataResult.attestedCredentialData?.publicKey.byteLength
  ).toBe(65);
});
