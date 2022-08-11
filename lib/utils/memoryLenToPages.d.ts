/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
declare const memoryLenToPages: (memoryLen: number, minPages?: number, maxPages?: number) => number;
export default memoryLenToPages;
//# sourceMappingURL=memoryLenToPages.d.ts.map