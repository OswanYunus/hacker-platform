export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    let message = body.message || res.statusText || "Request failed";
    if (typeof body.error === "string") {
      message = body.error;
    } else if (body.error?.fieldErrors) {
      const msgs = Object.entries(body.error.fieldErrors)
        .flatMap(([, errs]) => errs as string[])
        .filter(Boolean);
      if (msgs.length > 0) message = msgs.join(". ");
    } else if (body.error?.formErrors?.length) {
      message = (body.error.formErrors as string[]).join(". ");
    } else if (body.error) {
      message = JSON.stringify(body.error);
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};
