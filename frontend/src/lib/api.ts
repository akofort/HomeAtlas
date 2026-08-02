// Thin typed wrapper around the backend. Every call goes through `request`, so the session-expiry
// and error-message handling exists in exactly one place.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    // Session lives in an httpOnly cookie; without this it is never sent.
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      // FastAPI puts validation errors in `detail` as an array; flatten so the UI never renders
      // "[object Object]" at the user.
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: any) => d.msg).join(", ");
    } catch {
      /* keep the status line */
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const get = <T,>(path: string) => request<T>(path);
const post = <T,>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}) });
const patch = <T,>(path: string, body: unknown) =>
  request<T>(path, { method: "PATCH", body: JSON.stringify(body) });
const put = <T,>(path: string, body: unknown) =>
  request<T>(path, { method: "PUT", body: JSON.stringify(body) });
const del = <T,>(path: string) => request<T>(path, { method: "DELETE" });

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

export type Role = "ADMIN" | "MEMBER";

export interface User {
  id: string;
  username: string;
  role: Role;
  displayName: string;
  createdAt: string;
}

export interface ServiceInfo {
  port: number;
  service: string;
  explanation: string;
}

export interface System {
  id: string;
  kind: string;
  name: string;
  hostname: string;
  ip: string;
  mac: string;
  vendor: string;
  model: string;
  os: string;
  location: string;
  purpose: string;
  descriptionMd: string;
  url: string;
  docUrl: string;
  notes: string;
  importance: "critical" | "normal" | "low";
  parentId: string | null;
  status: "online" | "offline" | "unknown";
  discovered: number;
  confirmed: number;
  discoverySource: string;
  openPorts: number[] | null;
  services: ServiceInfo[] | null;
  extra: Record<string, any> | null;
  firstSeen: string;
  lastSeen: string;
  updatedAt: string;
  accountCount?: number;
}

export interface Account {
  id: string;
  systemId: string | null;
  label: string;
  category: string;
  username: string;
  url: string;
  notes: string;
  allowProbe: number;
  port: number;
  updatedAt: string;
  hasSecret: boolean;
  hasPassphrase: boolean;
}

export interface DocVersion {
  id: string;
  slug: string;
  title: string;
  generated: number;
  reason: string;
  createdAt: string;
  size: number;
  bodyMd?: string;
}

export interface ProbeFact {
  label: string;
  value: string;
}

export interface ProbeResult {
  ok: boolean;
  error: string;
  facts: Record<string, ProbeFact>;
}

export interface ProbeOutcome {
  ran: boolean;
  results: Record<string, ProbeResult>;
  purpose?: string;
  reason: string;
}

export interface DocPage {
  id: string;
  slug: string;
  topic: string;
  title: string;
  bodyMd: string;
  intro: string;
  generated: number;
  sortOrder: number;
  updatedAt: string;
}

export interface Scan {
  id: string;
  startedAt: string;
  finishedAt: string | null;
  status: "running" | "completed" | "failed";
  subnets: string;
  progress: number;
  phase: string;
  summary: Record<string, any> | null;
  log?: string;
}

export interface ChatMessage {
  id: string;
  chatId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface Chat {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export interface Dashboard {
  homeName: string;
  setupCompleted: boolean;
  counts: {
    total: number;
    online: number;
    offline: number;
    critical: number;
    accounts: number;
    documented: number;
  };
  byKind: Record<string, number>;
  kindLabels: Record<string, string>;
  criticalSystems: System[];
  recentlyChanged: System[];
  lastScan: Scan | null;
  llmConfigured: boolean;
}

export interface ModelOption {
  id: string;
  label: string;
  price_tier: string;
}

export interface SettingsResponse {
  settings: Record<string, any>;
  providers: Record<string, string>;
  catalog: Record<string, ModelOption[]>;
  ouiLoaded: boolean;
  ouiEntries: number;
  dockerAvailable: boolean;
}

export interface DiagnosticResult {
  explanation: string;
  [key: string]: any;
}

// ---------------------------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------------------------

export const api = {
  health: () => get<{ status: string; setupCompleted: boolean; userCount: number }>("/health"),

  login: (username: string, password: string) => post<{ user: User }>("/auth/login", { username, password }),
  logout: () => post<{ ok: boolean }>("/auth/logout"),
  me: () => get<{ user: User }>("/auth/me"),
  changePassword: (currentPassword: string, newPassword: string) =>
    post<{ ok: boolean }>("/auth/password", { currentPassword, newPassword }),

  listUsers: () => get<{ users: User[] }>("/users"),
  createUser: (body: { username: string; password: string; role: Role; displayName: string }) =>
    post<{ user: User }>("/users", body),
  deleteUser: (id: string) => del<{ ok: boolean }>(`/users/${id}`),

  getSettings: () => get<SettingsResponse>("/settings"),
  updateSettings: (patchBody: Record<string, any>) =>
    patch<{ settings: Record<string, any> }>("/settings", patchBody),
  testLlm: (provider: string, settings: Record<string, any>) =>
    post<{ ok: boolean; message: string; model: string }>("/settings/llm/test", { provider, settings }),
  refreshModels: (provider: string, settings: Record<string, any>) =>
    post<{ ok: boolean; message: string; models: ModelOption[] }>("/settings/llm/models", { provider, settings }),
  refreshOui: () => post<{ ok: boolean; message: string; entries: number }>("/settings/oui/refresh"),

  listSystems: (kind?: string) =>
    get<{ systems: System[]; kindLabels: Record<string, string> }>(`/systems${kind ? `?kind=${kind}` : ""}`),
  getSystem: (id: string) => get<{ system: System; accounts: Account[] }>(`/systems/${id}`),
  createSystem: (body: Partial<System>) => post<{ system: System }>("/systems", body),
  updateSystem: (id: string, body: Partial<System>) => patch<{ system: System }>(`/systems/${id}`, body),
  deleteSystem: (id: string) => del<{ ok: boolean }>(`/systems/${id}`),
  probeSystem: (id: string) => post<{ outcome: ProbeOutcome; system: System }>(`/systems/${id}/probe`),

  listAccounts: () => get<{ accounts: Account[] }>("/accounts"),
  createAccount: (body: Record<string, any>) => post<{ account: Account }>("/accounts", body),
  updateAccount: (id: string, body: Record<string, any>) => patch<{ account: Account }>(`/accounts/${id}`, body),
  revealSecret: (id: string) => get<{ secret: string }>(`/accounts/${id}/secret`),
  deleteAccount: (id: string) => del<{ ok: boolean }>(`/accounts/${id}`),

  listDocs: () => get<{ pages: Omit<DocPage, "bodyMd">[] }>("/docs"),
  getDoc: (slug: string) => get<{ page: DocPage }>(`/docs/${slug}`),
  saveDoc: (slug: string, bodyMd: string) => put<{ page: DocPage }>(`/docs/${slug}`, { bodyMd }),
  resetDoc: (slug: string) => post<{ page: DocPage }>(`/docs/${slug}/reset`),
  generateDocs: (useLlm: boolean) => post<{ generated: string[] }>("/docs/generate", { useLlm }),
  listDocVersions: (slug: string) => get<{ versions: DocVersion[] }>(`/docs/${slug}/versions`),
  getDocVersion: (slug: string, id: string) => get<{ version: DocVersion }>(`/docs/${slug}/versions/${id}`),
  restoreDocVersion: (slug: string, id: string) =>
    post<{ page: DocPage }>(`/docs/${slug}/versions/${id}/restore`),

  startScan: () => post<{ scanId: string }>("/scans"),
  listScans: () => get<{ scans: Scan[]; running: Scan | null }>("/scans"),
  getScan: (id: string) => get<{ scan: Scan }>(`/scans/${id}`),

  runDiagnostic: (tool: string, args: Record<string, any> = {}) =>
    post<{ result: DiagnosticResult }>("/diagnostics", { tool, args }),

  listChats: () => get<{ chats: Chat[] }>("/chats"),
  createChat: () => post<{ chat: Chat }>("/chats"),
  listMessages: (chatId: string) => get<{ messages: ChatMessage[] }>(`/chats/${chatId}/messages`),
  sendMessage: (chatId: string, message: string) =>
    post<{ message: ChatMessage; model: string; toolsUsed: string[] }>(`/chats/${chatId}/messages`, { message }),
  deleteChat: (chatId: string) => del<{ ok: boolean }>(`/chats/${chatId}`),

  dashboard: () => get<Dashboard>("/dashboard"),
  setup: (body: Record<string, any>) => post<{ ok: boolean; systems: number; accounts: number }>("/setup", body),
};
