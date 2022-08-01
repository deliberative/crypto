import dcrypto from "../src";
import utils from "../src/utils";

describe("Utils test suite.", () => {
  test("Base64 checker works.", () => {
    const message = "Some shit";
    expect(utils.isBase64(message)).toBe(false);
    const messageB64 = Buffer.from(message, "utf8").toString("base64");
    expect(utils.isBase64(messageB64)).toBe(true);
    const messageB64URL = Buffer.from(message, "utf8").toString("base64url");
    expect(utils.isBase64(messageB64URL)).toBe(true);
  });

  test("Browser checker works.", () => {
    expect(utils.isBrowser()).toBe(false);
  });

  test("Array equality checker works.", async () => {
    const hash1 = await dcrypto.sha512("Some message");
    const hash2 = await dcrypto.sha512("Some message");
    const hash3 = await dcrypto.sha512("Some other message");

    const areEqual = utils.arraysAreEqual(hash1, hash2);
    const areNotEqual = utils.arraysAreEqual(hash1, hash3);

    expect(areEqual).toBe(true);
    expect(areNotEqual).toBe(false);
  });

  test("Encode Uint8Array to base64 url-safe string works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const publicKeyString = utils.encodeToBase64(keypair.publicKey);
    expect(typeof publicKeyString === "string").toBe(true);
    expect(utils.isBase64(publicKeyString)).toBe(true);
  });

  test("Decode base64 url-safe string to Uint8Array works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const publicKeyString = utils.encodeToBase64(keypair.publicKey);
    const publicKey = utils.decodeFromBase64(publicKeyString);
    expect(typeof publicKey === typeof keypair.publicKey).toBe(true);
  });

  test("Choosing a random number from a range works.", async () => {
    const min = 1;
    const max = 1000000;
    const someNumber = await dcrypto.randomNumberInRange(min, max);
    const someOtherNumber = await dcrypto.randomNumberInRange(min, max);
    expect(min).toBeLessThanOrEqual(someNumber);
    expect(someNumber).toBeLessThanOrEqual(max);
    expect(someNumber === someOtherNumber).toBe(false);
  });

  test("Crypto random shuffling of array works.", async () => {
    const arrayOneElement = [1];
    const arrayOneElementShuffled = await dcrypto.arrayRandomShuffle(
      arrayOneElement,
    );
    expect(arrayOneElement[0] === arrayOneElementShuffled[0]).toBe(true);

    const someArray = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const shuffled = await dcrypto.arrayRandomShuffle(someArray);

    // Resulting array is of equal length.
    expect(shuffled.length === someArray.length).toBe(true);

    // Shuffled elements are the same as array.
    expect(someArray.sort().toString() === shuffled.sort().toString()).toBe(
      true,
    );

    const reshuffled = await dcrypto.arrayRandomShuffle(someArray);

    let everyElementInSamePlace = true;
    for (let i = 0; i < reshuffled.length; i++) {
      if (someArray[i] !== reshuffled[i]) {
        everyElementInSamePlace = false;
      }
    }

    expect(everyElementInSamePlace).toBe(false);
  });

  test("Random subset of array works.", async () => {
    const array = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    const subset = await dcrypto.arrayRandomSubset(array, array.length - 3);

    expect(subset.length).toBe(array.length - 3);

    for (let i = 0; i < subset.length; i++) {
      expect(array.includes(subset[i])).toBe(true);
    }
  });
});
