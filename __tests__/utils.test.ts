import dutils from "@deliberative/utils";

import dcrypto from "../src";

describe("Starting the cryptographic random utils test suite.", () => {
  test("Generation without module works.", async () => {
    const len = 34 * 1024;
    const message = await dcrypto.randomBytes(len);

    expect(message.length).toBe(len);
    expect(message[0] === message[Math.ceil((2 * len) / 3)]).toBe(false);
  });

  test("Generation with module works.", async () => {
    const len = 34 * 1024;
    const randomBytesMemory = dcrypto.loadWasmMemory.randomBytes(len);
    const randomBytesModule = await dcrypto.loadModule({
      wasmMemory: randomBytesMemory,
    });

    const initialMessage = await dcrypto.randomBytes(len, randomBytesModule);
    let anotherMessage: Uint8Array;
    for (let i = 0; i < 10; i++) {
      anotherMessage = await dcrypto.randomBytes(len, randomBytesModule);

      const condition =
        anotherMessage[0] === initialMessage[0] &&
        anotherMessage[Math.ceil((2 * len) / 3)] ===
          initialMessage[Math.ceil((2 * len) / 3)];

      expect(condition).toBe(false);
    }
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

  test("Random shuffling of array works.", async () => {
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

  it("Should be impossible to ask for more shuffled elements than original", async () => {
    const array = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    await expect(
      dcrypto.arrayRandomSubset(array, array.length + 1),
    ).rejects.toThrow("Not enough elements in the array");
  });

  const len = 64;
  const arr1 = new Uint8Array(len);
  const arr2 = new Uint8Array(len);
  arr1.fill(1);
  arr2.fill(2);

  const arr3 = new Uint8Array(len);
  arr3.fill(1);

  const arr4 = new Uint8Array(len);
  arr4.fill(4);

  const arrayOfArrays1: Uint8Array[] = [];
  arrayOfArrays1.push(arr2);
  arrayOfArrays1.push(arr4);
  arrayOfArrays1.push(arr2);

  test("Finding out if item is in array works.", async () => {
    const arrayOfArrays: Uint8Array[] = [];
    arrayOfArrays.push(arr4);
    arrayOfArrays.push(arr2);
    arrayOfArrays.push(arr1);
    arrayOfArrays.push(arr2);
    arrayOfArrays.push(arr4);
    const occurrence = await dcrypto.itemIndexInArray(arrayOfArrays, arr1);

    expect(occurrence).toBe(2);

    const occurrence1 = await dcrypto.itemIndexInArray(arrayOfArrays1, arr1);

    expect(occurrence1).toBe(-1);
  });

  test("Finding out the indexes of items in an array works.", async () => {
    const arrayOfArrays2: Uint8Array[] = [];
    arrayOfArrays2.push(arr4);
    arrayOfArrays2.push(arr2);

    const indexes = await dcrypto.itemsIndexesInArray(
      arrayOfArrays1,
      arrayOfArrays2,
    );

    expect(indexes[0]).toBe(1);
    expect(indexes[1]).toBe(0);
  });

  it("Should throw an error if one of the items is not in the array.", async () => {
    const arrayOfArrays3: Uint8Array[] = [new Uint8Array(len).fill(15)];

    await expect(
      dcrypto.itemsIndexesInArray(arrayOfArrays1, arrayOfArrays3),
    ).rejects.toThrow("Item with index 0 was not found in the array.");
  });

  interface SomeRandomInterface {
    val1: string;
    val2: string;
    val3: string;
  }

  const arr5: SomeRandomInterface = {
    val1: "1",
    val2: "2",
    val3: "3",
  };

  const arr6: SomeRandomInterface = {
    val1: "5",
    val2: "6",
    val3: "7",
  };

  const arr7: SomeRandomInterface = {
    val1: "10",
    val2: "20",
    val3: "30",
  };

  const arrayOfArrays3: SomeRandomInterface[] = [arr5, arr6, arr7];

  const someRandomInterfaceSerializer = (item: SomeRandomInterface) => {
    const uint8 = new Uint8Array(4 * 3 * Uint8Array.BYTES_PER_ELEMENT);

    uint8.set(dutils.numberToUint8Array(Number(item.val1)));
    uint8.set(
      dutils.numberToUint8Array(Number(item.val2)),
      4 * Uint8Array.BYTES_PER_ELEMENT,
    );
    uint8.set(
      dutils.numberToUint8Array(Number(item.val3)),
      8 * Uint8Array.BYTES_PER_ELEMENT,
    );

    return uint8;
  };

  test("Finding out if item is in array with serializer works.", async () => {
    const occurrence = await dcrypto.itemIndexInArray(
      arrayOfArrays3,
      arr6,
      someRandomInterfaceSerializer,
    );

    expect(occurrence).toBe(1);
  });

  test("Finding out the indexes of items in an array with serializer works.", async () => {
    const arrayOfArrays4: SomeRandomInterface[] = [];
    arrayOfArrays4.push(arr7);
    arrayOfArrays4.push(arr5);

    const indexes = await dcrypto.itemsIndexesInArray(
      arrayOfArrays3,
      arrayOfArrays4,
      someRandomInterfaceSerializer,
    );

    expect(indexes[0]).toBe(2);
    expect(indexes[1]).toBe(0);
  });
});
