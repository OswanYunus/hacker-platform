import clsx from "clsx";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-[#A4221B] text-white",
  high: "bg-[#B5541A] text-white",
  medium: "bg-[#946C0D] text-white",
  low: "bg-[#345C82] text-white",
  info: "bg-[#5B6472] text-white",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-sm px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide",
        SEVERITY_STYLES[key] ?? "bg-ink-700 text-white",
      )}
    >
      {severity}
    </span>
  );
}

const CONFIDENCE_STYLES: Record<string, string> = {
  confirmed: "text-[#2E6B1F]",
  high: "text-[#4A6B1F]",
  medium: "text-[#8C6A14]",
  low: "text-[#8C5B24]",
};

export function ConfidenceLabel({ confidence }: { confidence: string }) {
  return (
    <span className={clsx("text-2xs font-medium", CONFIDENCE_STYLES[confidence.toLowerCase()] ?? "text-paper-200")}>
      {confidence}
    </span>
  );
}
