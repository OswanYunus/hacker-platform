import Link from "next/link";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/projects", label: "Projects" },
];

export function AppShell({
  children,
  projectNav,
  activeHref,
}: {
  children: React.ReactNode;
  projectNav?: { base: string; items: Array<{ href: string; label: string }> };
  activeHref?: string;
}) {
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col justify-between bg-ink-950 text-paper-100">
        <div>
          <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-4">
            <div className="flex h-6 w-6 items-center justify-center rounded-sm bg-accent text-xs font-bold text-ink-950">
              H
            </div>
            <span className="font-semibold tracking-tight">Hacker</span>
          </div>

          <nav className="px-2 py-3">
            {NAV_ITEMS.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={clsx(
                  "block rounded-sm px-3 py-1.5 text-sm text-paper-200 hover:bg-ink-800 hover:text-white",
                  activeHref === item.href && "bg-ink-800 text-white",
                )}
              >
                {item.label}
              </Link>
            ))}

            {projectNav && (
              <div className="mt-4 border-t border-ink-800 pt-3">
                <div className="px-3 pb-1 text-2xs uppercase tracking-wide text-paper-200/50">Project</div>
                {projectNav.items.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={clsx(
                      "block rounded-sm px-3 py-1.5 text-sm text-paper-200 hover:bg-ink-800 hover:text-white",
                      activeHref === item.href && "bg-ink-800 text-white",
                    )}
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            )}
          </nav>
        </div>

        <div className="border-t border-ink-800 px-4 py-3 text-2xs text-paper-200/60">
          Authorized testing only. Every scan requires an active, attributed scope.
        </div>
      </aside>

      <main className="flex-1 bg-paper-50">{children}</main>
    </div>
  );
}
