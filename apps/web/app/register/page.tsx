"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { Button, Field, inputClass } from "@/components/ui";
import { PasswordInput } from "@/components/PasswordInput";

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState({ name: "", email: "", password: "", organizationName: "" });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showTerms, setShowTerms] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.post("/api/auth/register", form);
      router.push("/projects");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create account. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-paper-50 px-4 py-8">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-sm bg-ink-950 text-sm font-bold text-white">H</div>
          <span className="text-lg font-semibold text-ink-950">Hacker</span>
        </div>

        <div className="rounded-md border border-paper-200 bg-white p-6">
          <h1 className="text-base font-semibold text-ink-900">Create your account</h1>
          <p className="mt-1 text-xs text-ink-600">
            Authorized web application security assessment platform.
          </p>

          <form onSubmit={onSubmit} className="mt-5 space-y-4">
            <Field label="Full name">
              <input required className={inputClass} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Organization name">
              <input
                required
                className={inputClass}
                value={form.organizationName}
                onChange={(e) => setForm({ ...form, organizationName: e.target.value })}
              />
            </Field>
            <Field label="Email">
              <input type="email" required className={inputClass} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </Field>
            <Field label="Password" hint="At least 8 characters and one special character.">
              <PasswordInput
                required
                minLength={8}
                maxLength={128}
                autoComplete="new-password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
            </Field>
            {error && <p className="text-xs text-[#A4221B]">{error}</p>}

            <div className="pt-1 text-2xs text-ink-600 leading-normal">
              By clicking Create account, you are agreeing to our{" "}
              <button
                type="button"
                onClick={() => setShowTerms(true)}
                className="font-medium text-ink-900 underline hover:text-ink-950"
              >
                Terms and Conditions
              </button>.
            </div>

            <Button type="submit" disabled={loading} className="w-full justify-center">
              {loading ? "Creating account…" : "Create account"}
            </Button>
          </form>
        </div>

        <p className="mt-4 text-center text-xs text-ink-600">
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-ink-900 underline">
            Sign in
          </Link>
        </p>
      </div>

      {/* Terms & Conditions Modal */}
      {showTerms && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/40 p-4">
          <div className="relative max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-md border border-paper-200 bg-white p-6 shadow-lg">
            <div className="flex items-start justify-between border-b border-paper-200 pb-3">
              <div>
                <h2 className="text-base font-semibold text-ink-950">Terms and Conditions</h2>
                <p className="text-xs text-ink-500">Platform Usage Agreement &amp; Authorized Testing Attestation</p>
              </div>
              <button
                type="button"
                onClick={() => setShowTerms(false)}
                className="text-xs font-semibold text-ink-500 hover:text-ink-950"
              >
                Close ✕
              </button>
            </div>

            <div className="space-y-4 py-4 text-xs leading-relaxed text-ink-700">
              <section>
                <h3 className="font-semibold text-ink-900 mb-1">1. Purpose of the Platform</h3>
                <p>
                  Hacker is an automated web security testing and vulnerability assessment platform. The system is designed to perform authorized discovery, crawling, passive analysis, and active vulnerability probing (including injection testing, access control verification, sensitive path discovery, and authentication analysis) on web applications.
                </p>
              </section>

              <section>
                <h3 className="font-semibold text-ink-900 mb-1">2. Mandatory Legal Authorization</h3>
                <p>
                  You expressly attest and warrant that you own or have received formal, written authorization from the legal owner of every domain, hostname, IP address, and web application configured in this platform. Performing security scans against computer systems without explicit authorization is illegal under computer misuse legislation worldwide. You agree never to configure or scan third-party assets without verified permission.
                </p>
              </section>

              <section>
                <h3 className="font-semibold text-ink-900 mb-1">3. Nature of Active Testing &amp; Traffic</h3>
                <p>
                  Active security testing involves transmitting automated test payloads and simulating real-world vulnerability exploitation checks (such as SQL injection indicators, XSS reflection, path traversal checks, and sequential parameter checks). While designed to be non-destructive, you understand that active testing generates network requests and may affect server load. You are responsible for scheduling scans during appropriate maintenance windows and configuring rate limits.
                </p>
              </section>

              <section>
                <h3 className="font-semibold text-ink-900 mb-1">4. Data Privacy &amp; Credential Encryption</h3>
                <p>
                  Sensitive authentication secrets (such as session cookies, bearer tokens, and API keys) provided for authenticated scanning are envelope-encrypted using AES-256-GCM at rest. Scan findings, raw observations, and audit trails belong strictly to your organization and are never shared or made public.
                </p>
              </section>

              <section>
                <h3 className="font-semibold text-ink-900 mb-1">5. Limitation of Liability</h3>
                <p>
                  This platform is provided as an engineering and assessment tool. You assume full responsibility for all activities conducted under your account and for the targets submitted. To the maximum extent permitted by law, the platform creators and operators are not liable for any service degradation, target downtime, or damages resulting from scans initiated by you.
                </p>
              </section>
            </div>

            <div className="border-t border-paper-200 pt-3 flex justify-end">
              <Button onClick={() => setShowTerms(false)}>
                I Understand
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
