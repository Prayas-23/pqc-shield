import { useEffect, useState } from "react";

export interface ApiState<T> { data: T | null; error: string | null; loading: boolean }

/** GET a JSON route of the read-only API. Errors carry the URL and the status so the UI can say what failed. */
export async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal });
  if (!res.ok) {
    let detail: unknown = res.statusText;
    try { detail = ((await res.json()) as { detail?: unknown }).detail ?? detail; } catch { /* body was not JSON */ }
    throw new Error(`${url}: ${res.status} ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
  return (await res.json()) as T;
}

export function useApi<T>(url: string | null): ApiState<T> {
  const [state, setState] = useState<ApiState<T>>({ data: null, error: null, loading: url !== null });
  useEffect(() => {
    if (url === null) { setState({ data: null, error: null, loading: false }); return; }
    const ctl = new AbortController();
    setState((s) => ({ data: s.data, error: null, loading: true }));
    getJson<T>(url, ctl.signal)
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return;
        setState({ data: null, error: e instanceof Error ? e.message : String(e), loading: false });
      });
    return () => ctl.abort();
  }, [url]);
  return state;
}

export function streamUrl(params: Record<string, string | number>): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const q = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]));
  return `${proto}://${window.location.host}/api/stream?${q.toString()}`;
}
