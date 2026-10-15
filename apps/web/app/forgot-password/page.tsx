"use client";

import Link from "next/link";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Button, Field, inputClass } from "@/components/ui";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setMessage(null);
    setError(null);
    setLoading(true);
    try {
      const result = await api.post<{ message: string }>("/api/auth/forgot-password", { email });
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 503
        ? "Password reset email has not been configured for this deployment yet. Contact the administrator."
        : "Could not request a reset link. Check the email address and try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-paper-50 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-sm bg-ink-950 text-sm font-bold text-white">H</div>
          <span className="text-lg font-semibold text-ink-950">Hacker</span>
        </div>
        <div className="rounded-md border border-paper-200 bg-white p-6">
          <h1 className="text-base font-semibold text-ink-900">Reset your password</h1>
          <p className="mt-1 text-xs text-ink-600">We’ll email a one-time link if an account exists for that address.</p>
          <form onSubmit={onSubmit} className="mt-5 space-y-4">
            <Field label="Email">
              <input type="email" autoComplete="email" required className={inputClass} value={email} onChange={(event) => setEmail(event.target.value)} />
            </Field>
            {message && <p role="status" className="text-xs text-ink-700">{message}</p>}
            {error && <p role="alert" className="text-xs text-[#A4221B]">{error}</p>}
            <Button type="submit" disabled={loading} className="w-full justify-center">{loading ? "Sending…" : "Send reset link"}</Button>
          </form>
        </div>
        <p className="mt-4 text-center text-xs text-ink-600"><Link href="/login" className="font-medium text-ink-900 underline">Back to sign in</Link></p>
      </div>
    </div>
  );
}
