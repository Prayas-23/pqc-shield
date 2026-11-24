/** Number formatting. Every number shown carries its unit; null/NaN is shown as "n/a". */
const NA = "n/a";
const ok = (x: number | null | undefined): x is number => typeof x === "number" && Number.isFinite(x);

export const fmtInt = (x: number | null | undefined): string => (ok(x) ? Math.round(x).toLocaleString("en-US") : NA);
export const fmtBytes = (x: number | null | undefined): string => (ok(x) ? `${fmtInt(x)} B` : NA);
export const fmtSigned = (x: number | null | undefined, unit = ""): string =>
  ok(x) ? `${x > 0 ? "+" : x < 0 ? "−" : ""}${Math.abs(Math.round(x)).toLocaleString("en-US")}${unit}` : NA;
export const fmtPct = (x: number | null | undefined, digits = 1): string => (ok(x) ? `${(100 * x).toFixed(digits)} %` : NA);
export const fmtNum = (x: number | null | undefined, digits = 3): string => (ok(x) ? x.toFixed(digits) : NA);
export const fmtP = (x: number | null | undefined): string => (ok(x) ? (x < 0.001 ? "< 0.001" : x.toFixed(3)) : NA);
export const shortSha = (s: string): string =>
  /^[0-9a-f]{12,}(-dirty)?$/.test(s) ? s.slice(0, 8) + (s.endsWith("-dirty") ? "-dirty" : "") : s;
