"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { Button, Field, inputClass } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.post("/api/auth/login", { email, password });
      router.push("/projects");
    } catch (err) {
      setError(err instanceof ApiError ? "Invalid email or password." : "Something went wrong. Try again.");
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
          <h1 className="text-base font-semibold text-ink-900">Sign in</h1>
          <p className="mt-1 text-xs text-ink-600">Authorized security testing for applications you own or have permission to assess.</p>

          <form onSubmit={onSubmit} className="mt-5 space-y-4">
            <Field label="Email">
              <input type="email" required className={inputClass} value={email} onChange={(e) => setEmail(e.target.value)} />
            </Field>
            <Field label="Password">
              <input type="password" required className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            {error && <p className="text-xs text-[#A4221B]">{error}</p>}
            <Button type="submit" disabled={loading} className="w-full justify-center">
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </div>

        <p className="mt-4 text-center text-xs text-ink-600">
          No account?{" "}
          <Link href="/register" className="font-medium text-ink-900 underline">
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}
