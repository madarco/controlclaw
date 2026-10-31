/** The API's rule for the admin password (cc-local `admin.rs`). */
export const MIN_PASSWORD = 12;

/** Characters as the API counts them (Rust `chars()`): code points, not UTF-16 units. */
export function passwordLength(s: string): number {
  return Array.from(s).length;
}
