import type { HttpExchange, TechnologyFingerprint } from "./types.js";

interface Rule {
  name: string;
  category: TechnologyFingerprint["category"];
  test: (ex: HttpExchange) => string | null; // returns version string or "" if matched without a version
}

const RULES: Rule[] = [
  {
    name: "nginx",
    category: "server",
    test: (ex) => matchHeader(ex, "server", /nginx\/?([\d.]+)?/i),
  },
  {
    name: "Apache",
    category: "server",
    test: (ex) => matchHeader(ex, "server", /apache\/?([\d.]+)?/i),
  },
  {
    name: "Express",
    category: "framework",
    test: (ex) => matchHeader(ex, "x-powered-by", /express/i),
  },
  {
    name: "PHP",
    category: "language",
    test: (ex) => matchHeader(ex, "x-powered-by", /php\/?([\d.]+)?/i),
  },
  {
    name: "ASP.NET",
    category: "framework",
    test: (ex) => matchHeader(ex, "x-powered-by", /asp\.net/i) ?? matchHeader(ex, "x-aspnet-version", /([\d.]+)/i),
  },
  {
    name: "React",
    category: "library",
    test: (ex) => bodyContains(ex, /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom/i),
  },
  {
    name: "Next.js",
    category: "framework",
    test: (ex) => bodyContains(ex, /__NEXT_DATA__|\/_next\/static\//i),
  },
  {
    name: "Vue.js",
    category: "library",
    test: (ex) => bodyContains(ex, /data-v-[0-9a-f]{6,}|__vue__/i),
  },
  {
    name: "WordPress",
    category: "cms",
    test: (ex) => bodyContains(ex, /wp-content|wp-includes/i),
  },
  {
    name: "Django",
    category: "framework",
    test: (ex) => bodyContains(ex, /csrfmiddlewaretoken/i),
  },
  {
    name: "Ruby on Rails",
    category: "framework",
    test: (ex) => matchHeader(ex, "x-runtime", /.+/) ?? bodyContains(ex, /authenticity_token/i),
  },
  {
    name: "Cloudflare",
    category: "other",
    test: (ex) => matchHeader(ex, "server", /cloudflare/i) ?? matchHeader(ex, "cf-ray", /.+/),
  },
];

export function detectTechnologies(exchanges: HttpExchange[]): TechnologyFingerprint[] {
  const found = new Map<string, TechnologyFingerprint>();

  for (const ex of exchanges) {
    for (const rule of RULES) {
      if (found.has(rule.name)) continue;
      const match = rule.test(ex);
      if (match !== null) {
        found.set(rule.name, {
          name: rule.name,
          category: rule.category,
          version: match || undefined,
          confidence: match ? "high" : "medium",
          evidence: `Detected on ${ex.request.url}`,
        });
      }
    }
  }
  return Array.from(found.values());
}

function matchHeader(ex: HttpExchange, header: string, pattern: RegExp): string | null {
  const value = Object.entries(ex.response.headers).find(([k]) => k.toLowerCase() === header)?.[1];
  if (!value) return null;
  const m = value.match(pattern);
  if (!m) return null;
  return m[1] ?? "";
}

function bodyContains(ex: HttpExchange, pattern: RegExp): string | null {
  const body = ex.response.body ?? ex.response.bodyPreview;
  if (!body) return null;
  return pattern.test(body) ? "" : null;
}
