export function projectNavItems(projectId: string) {
  const base = `/projects/${projectId}`;
  return {
    base,
    items: [
      { href: base, label: "Overview" },
      { href: `${base}/scope`, label: "Scope & authorization" },
      { href: `${base}/scans`, label: "Scans" },
      { href: `${base}/findings`, label: "Findings" },
      { href: `${base}/audit`, label: "Audit trail" },
    ],
  };
}
