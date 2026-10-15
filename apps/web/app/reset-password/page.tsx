import Link from "next/link";
import { ResetPasswordForm } from "@/components/ResetPasswordForm";

export default async function ResetPasswordPage({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token } = await searchParams;
  return (
    <div className="flex min-h-screen items-center justify-center bg-paper-50 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-sm bg-ink-950 text-sm font-bold text-white">H</div>
          <span className="text-lg font-semibold text-ink-950">Hacker</span>
        </div>
        <div className="rounded-md border border-paper-200 bg-white p-6">
          <h1 className="text-base font-semibold text-ink-900">Choose a new password</h1>
          <p className="mt-1 text-xs text-ink-600">Use at least 8 characters and include a special character.</p>
          <ResetPasswordForm token={token ?? ""} />
        </div>
        <p className="mt-4 text-center text-xs text-ink-600"><Link href="/login" className="font-medium text-ink-900 underline">Back to sign in</Link></p>
      </div>
    </div>
  );
}
