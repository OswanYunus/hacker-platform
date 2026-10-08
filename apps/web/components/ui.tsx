import clsx from "clsx";

export function Panel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={clsx("rounded-md border border-paper-200 bg-white", className)}>{children}</div>;
}

export function PanelHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between border-b border-paper-200 px-4 py-3">
      <div>
        <h2 className="text-sm font-semibold text-ink-900">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-ink-600">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Button({
  children,
  variant = "primary",
  type = "button",
  onClick,
  disabled,
  className,
}: {
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  type?: "button" | "submit";
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
}) {
  const styles: Record<string, string> = {
    primary: "bg-ink-950 text-white hover:bg-ink-800 disabled:bg-ink-600",
    secondary: "bg-white text-ink-900 border border-paper-200 hover:bg-paper-100",
    danger: "bg-[#A4221B] text-white hover:bg-[#8A1C16]",
    ghost: "text-ink-700 hover:bg-paper-100",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        "rounded-sm px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60",
        styles[variant],
        className,
      )}
    >
      {children}
    </button>
  );
}

export function StatCard({ label, value, tone }: { label: string; value: string | number; tone?: "critical" | "high" | "default" }) {
  const toneClass =
    tone === "critical" ? "text-[#A4221B]" : tone === "high" ? "text-[#B5541A]" : "text-ink-900";
  return (
    <div className="rounded-md border border-paper-200 bg-white px-4 py-3">
      <div className="text-2xs uppercase tracking-wide text-ink-600">{label}</div>
      <div className={clsx("mt-1 text-2xl font-semibold tabular-nums", toneClass)}>{value}</div>
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-ink-800">{label}</span>
      {hint && <span className="mt-0.5 block text-2xs text-ink-600">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

export const inputClass =
  "w-full rounded-sm border border-paper-200 bg-white px-2.5 py-1.5 text-sm text-ink-900 placeholder:text-ink-600/50 focus:border-ink-700 focus:outline-none focus:ring-1 focus:ring-ink-700";
