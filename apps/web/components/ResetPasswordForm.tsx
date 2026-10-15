"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { Button, Field } from "@/components/ui";
import { PasswordInput } from "@/components/PasswordInput";

export function ResetPasswordForm({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.post("/api/auth/reset-password", { token, password });
      setComplete(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reset the password. Request a new link and try again.");
    } finally {
      setLoading(false);
    }
  }

  if (complete) {
    return <div className="mt-5 space-y-3"><p role="status" className="text-xs text-ink-700">Password updated. You can now sign in with your new password.</p><Link href="/login" className="inline-block text-xs font-medium text-ink-900 underline">Go to sign in</Link></div>;
  }

  return (
    <form onSubmit={onSubmit} className="mt-5 space-y-4">
      <Field label="New password" hint="At least 8 characters and one special character.">
        <PasswordInput autoComplete="new-password" required minLength={8} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} />
      </Field>
      {error && <p role="alert" className="text-xs text-[#A4221B]">{error}</p>}
      <Button type="submit" disabled={loading || token.length !== 64} className="w-full justify-center">{loading ? "Updating…" : "Update password"}</Button>
      {token.length !== 64 && <p className="text-xs text-[#A4221B]">This reset link is incomplete or invalid.</p>}
    </form>
  );
}
