/**
 * A typed client for a standalone firewall's panel API (docs/standalone/panel-api.md), generated
 * from the Rust route table: `schema.ts` comes from `openapi.json` (`pnpm generate`).
 *
 * The session is a cookie the browser keeps; every write sends the session's CSRF token, which the
 * client takes from `/api/setup`, `/api/login` or `/api/session` by itself.
 */
import type { paths } from "./schema";

export type { components, paths } from "./schema";
export type Schemas = import("./schema").components["schemas"];

type Method = "get" | "post" | "put" | "patch" | "delete";
type Op<P extends keyof paths, M extends Method> = NonNullable<paths[P][M]>;
type PathsWith<M extends Method> = { [P in keyof paths]: paths[P][M] extends undefined | never ? never : P }[keyof paths];

type Json<C> = C extends { content: { "application/json": infer T } } ? T : never;
/** What a route answers on success. */
export type Answer<P extends keyof paths, M extends Method> = Op<P, M> extends { responses: { 200: infer R } } ? Json<R> : never;
type BodyOf<O> = O extends { requestBody: infer B } ? Json<B> : never;
type PathOf<O> = O extends { parameters: { path: infer A } } ? (A extends Record<string, unknown> ? A : never) : never;
type QueryOf<O> = O extends { parameters: { query?: infer Q } } ? (Q extends Record<string, unknown> ? Q : never) : never;

/** What a call takes: `path` for `{id}` parts, `query`, and `body` for a write. */
export type Options<P extends keyof paths, M extends Method> = ([PathOf<Op<P, M>>] extends [never] ? { path?: undefined } : { path: PathOf<Op<P, M>> }) &
  ([QueryOf<Op<P, M>>] extends [never] ? { query?: undefined } : { query?: QueryOf<Op<P, M>> }) &
  ([BodyOf<Op<P, M>>] extends [never] ? { body?: undefined } : { body: BodyOf<Op<P, M>> });

/** A refusal: the status and the API's `{error}`. */
export class FwApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "FwApiError";
  }
}

export interface FwApiOptions {
  /** Where the API is; the page's own origin when left out. */
  baseUrl?: string;
  fetch?: typeof fetch;
}

function fill(path: string, params: Record<string, unknown> | undefined): string {
  return path.replace(/\{(\w+)\}/g, (_, k: string) => encodeURIComponent(String(params?.[k] ?? "")));
}

function search(query: Record<string, unknown> | undefined): string {
  if (!query) return "";
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
}

export function createFwApi(opts: FwApiOptions = {}) {
  const base = opts.baseUrl?.replace(/\/$/, "") ?? "";
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  let csrf: string | null = null;

  async function request<P extends keyof paths, M extends Method>(method: M, path: P, o?: Options<P, M>): Promise<Answer<P, M>> {
    const { path: params, query, body } = (o ?? {}) as { path?: Record<string, unknown>; query?: Record<string, unknown>; body?: unknown };
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (method !== "get" && csrf) headers["x-csrf-token"] = csrf;
    const res = await doFetch(`${base}${fill(path as string, params)}${search(query)}`, {
      method: method.toUpperCase(),
      headers,
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const message = (data as { error?: unknown } | null)?.error;
      throw new FwApiError(res.status, typeof message === "string" ? message : `HTTP ${res.status}`, data);
    }
    const token = (data as { csrf?: unknown } | null)?.csrf;
    if (typeof token === "string" && (path === "/api/login" || path === "/api/setup" || path === "/api/session")) csrf = token;
    if (path === "/api/logout") csrf = null;
    return data as Answer<P, M>;
  }

  return {
    request,
    get: <P extends PathsWith<"get">>(path: P, o?: Options<P, "get">) => request("get", path, o),
    post: <P extends PathsWith<"post">>(path: P, o?: Options<P, "post">) => request("post", path, o),
    put: <P extends PathsWith<"put">>(path: P, o: Options<P, "put">) => request("put", path, o),
    patch: <P extends PathsWith<"patch">>(path: P, o: Options<P, "patch">) => request("patch", path, o),
    delete: <P extends PathsWith<"delete">>(path: P, o?: Options<P, "delete">) => request("delete", path, o),
    /** The CSRF token the client holds (after a sign-in or a session read). */
    csrf: () => csrf,
  };
}

export type FwApi = ReturnType<typeof createFwApi>;
