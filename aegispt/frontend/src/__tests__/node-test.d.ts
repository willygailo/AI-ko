declare module "node:test" {
  export function describe(name: string, fn: () => void | Promise<void>): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export function beforeEach(fn: () => void | Promise<void>): void;
  export function afterEach(fn: () => void | Promise<void>): void;
}

declare module "node:assert/strict" {
  export function equal<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
  export function notEqual(actual: unknown, expected: unknown, message?: string): void;
  export function deepEqual(actual: unknown, expected: unknown, message?: string): void;
  export function ok(value: unknown, message?: string): asserts value;
  export function match(str: string, regexp: RegExp, message?: string): void;
  export function doesNotMatch(str: string, regexp: RegExp, message?: string): void;
  export function rejects(
    block: (() => Promise<unknown>) | Promise<unknown>,
    error?: RegExp | ((err: unknown) => boolean),
    message?: string
  ): Promise<void>;
}
