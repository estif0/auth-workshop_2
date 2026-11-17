// Injectable clock — every caller of Date.now() in this codebase uses this
// instead. Tests freeze time by passing () => fixedTimestamp.
// Production code uses the default: () => Date.now().
export type Clock = () => number;
export const realClock: Clock = () => Date.now();
