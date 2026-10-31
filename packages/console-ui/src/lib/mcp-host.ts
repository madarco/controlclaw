/** A server's host for display (`mcp.example.com`), or the text as it is when it is not a URL. Client-safe. */
export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
