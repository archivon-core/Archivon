import React, { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

declare global {
  interface Window {
    __ARCHIVON_PUBLIC_PATH__?: string;
  }
}

const TTL_TICK_WARNING_SECONDS = 30;

type Role = "super_admin" | "admin" | "client";
type AdminSection = "storage" | "users" | "access" | "compute" | "audit";

type User = {
  id: string;
  role: Role;
  username: string;
  must_change_password: boolean;
  is_blocked: boolean;
  description?: string;
  created_at: string;
  last_login_at?: string;
};

type BootstrapStatus = {
  required: boolean;
  super_admin_count: number;
  min_password_length: number;
};

type SystemStatus = {
  status: string;
  phase: string;
  environment: string;
  checks?: Record<string, string>;
  migrations?: {
    latest_version: number | string;
    applied_migrations: number;
  };
  kms?: KMSStatus;
};

type KMSStatus = {
  provider: string;
  state: string;
  available: boolean;
  key_id: string;
  algorithm: string;
  source?: string;
  format?: string;
  fingerprint?: string;
  reason?: string;
  checked_at: string;
  min_key_bytes: number;
};

type AuthResponse = {
  user: User;
};

type AuthSessionPolicy = {
  enabled: boolean;
  client_mode: string;
  admin_mode: string;
  super_admin_mode: string;
  auth_ttl_hours: number;
  allowed_auth_ttl_hours: number[];
};

type AuthSettingsResponse = {
  policy: AuthSessionPolicy;
  update_role_required: string;
};

type UsersResponse = {
  users: User[];
};

type CreateUserResponse = {
  user: User;
  temporary_password: string;
};

type DeleteUserResponse = {
  deleted_user_id: string;
  username: string;
  role: Role;
  revoked_sessions: number;
  canceled_jobs: number;
  deleted_pow_jobs: number;
  deleted_rights: number;
};

type ProtectedFolder = {
  id: string;
  name: string;
  description?: string;
  status: string;
  created_at: string;
  updated_at: string;
  file_count: number;
  total_bytes: number;
  unlock_usernames: string[];
  access?: AccessRights;
  pow_policy: FolderPoWPolicy;
};

type ClientFolder = {
  id: string;
  name: string;
  description?: string;
  status: string;
  file_count: number;
  total_bytes: number;
  access?: AccessRights;
};

type FolderPoWPolicy = {
  required_hashrate_ths: number;
  hashrate_tolerance_percent: number;
  proof_window_seconds: number;
  max_proof_attempts: number;
};

type ProtectedFile = {
  id: string;
  folder_id: string;
  name: string;
  path: string;
  size_bytes: number;
  plaintext_sha256: string;
  storage_object_id: string;
  chunk_count: number;
  status: string;
  created_at: string;
  updated_at: string;
};

type FoldersResponse = {
  folders: ProtectedFolder[];
};

type ClientFoldersResponse = {
  folders: ClientFolder[];
};

type FilesResponse = {
  files: ProtectedFile[];
};

type ClientFile = {
  id: string;
  folder_id: string;
  name: string;
  path: string;
  size_bytes: number;
  plaintext_sha256: string;
  status: string;
};

type FileVerification = {
  status: "checking" | "matched" | "mismatched" | "error";
  checked_name: string;
  checked_sha256?: string;
  message: string;
  checked_at: string;
};

type TreeFile = {
  id: string;
  name: string;
  path?: string;
  size_bytes: number;
};

type FileTreeNode<T extends TreeFile> = {
  name: string;
  path: string;
  folders: FileTreeNode<T>[];
  files: T[];
  file_count: number;
  total_bytes: number;
};

type ClientFilesResponse = {
  files: ClientFile[];
};

type CreateFolderResponse = {
  folder: ProtectedFolder;
};

type DeleteFolderResponse = {
  deleted_folder_id: string;
  deleted_files: number;
  deleted_bytes: number;
};

type DeleteFileResponse = {
  deleted_file_id: string;
  folder_id: string;
};

type UploadFileResponse = {
  file: ProtectedFile;
};

type ImportFolderBackupResponse = {
  folder: ProtectedFolder;
  imported_files: number;
  imported_collections: number;
};

type AdminDAVCredentials = {
  dav_url: string;
  dav_username: string;
  dav_password: string;
  expires_at: string;
};

type AdminDAVSessionResponse = {
  session: AdminDAVCredentials;
};

type AccessRights = {
  can_unlock_and_access: boolean;
  expires_at?: string;
};

type FolderPermission = AccessRights & {
  user_id: string;
  username: string;
  role: Role;
  updated_at?: string;
};

type PermissionsResponse = {
  permissions: FolderPermission[];
};

type UpdatePermissionResponse = {
  permission: FolderPermission;
};

type AccessPolicy = {
  required_hashrate_ths: number;
  min_workers: number;
  hashrate_tolerance_percent: number;
  proof_window_seconds: number;
  max_proof_attempts: number;
  job_timeout_minutes: number;
  session_ttl_minutes: number;
  allowed_session_ttl_minutes: number[];
  single_active_session: boolean;
  heartbeat_enabled: boolean;
  upload_pow_required: boolean;
};

type AccessSettingsResponse = {
  policy: AccessPolicy;
  required_work_th: number;
  accepted_hashrate_ths: number;
  estimated_window: string;
  update_role_required: string;
};

type PowJob = {
  id: string;
  user_id: string;
  username?: string;
  folder_id: string;
  status: "queued" | "running" | "succeeded" | "failed" | "canceled" | "timeout";
  required_hashrate_ths: number;
  required_work_th: number;
  observed_hashrate_ths?: number;
  min_workers: number;
  hashrate_tolerance_percent: number;
  proof_window_seconds: number;
  max_proof_attempts: number;
  timeout_seconds: number;
  queue_position: number;
  failure_reason?: string;
  valid_work_th: number;
  valid_worker_count: number;
  created_at: string;
  started_at?: string;
  finished_at?: string;
};

type ClientPowJob = {
  id: string;
  folder_id: string;
  status: "queued" | "running" | "succeeded" | "failed" | "canceled" | "timeout";
  queue_position: number;
  created_at: string;
  started_at?: string;
  finished_at?: string;
};

type AccessSession = {
  id: string;
  user_id: string;
  username?: string;
  folder_id: string;
  pow_job_id?: string;
  status: "active" | "closed" | "expired" | "revoked";
  opened_at: string;
  expires_at: string;
  closed_at?: string;
  close_reason?: string;
  dav_url?: string;
  dav_username?: string;
  dav_password?: string;
};

type ClientJobsResponse = {
  jobs: ClientPowJob[];
};

type ClientJobResponse = {
  job: ClientPowJob;
  session?: AccessSession;
};

type SessionsResponse = {
  sessions: AccessSession[];
};

type SessionResponse = {
  session: AccessSession;
};

type TerminalLine = {
  at: string;
  source: string;
  level: string;
  message: string;
};

type UploadProgress = {
  status: "running" | "done" | "error";
  total: number;
  completed: number;
  current_file: string;
  current_loaded?: number;
  current_total?: number;
  error_message?: string;
};

type TerminalResponse = {
  lines: TerminalLine[];
  node_link_ok: boolean;
  updated_at: string;
};

type NodeLinkResponse = {
  node_link_ok: boolean;
  updated_at: string;
};

type QueueResponse = {
  policy: AccessPolicy;
  jobs: PowJob[];
  active_sessions: AccessSession[];
};

type ComputePolicy = {
  enabled: boolean;
  bind_address: string;
  stratum_port: number;
  share_difficulty: number;
  extranonce2_size: number;
  password_configured: boolean;
  password_updated_at?: string;
};

type ComputeRuntime = {
  running: boolean;
  listen_address: string;
  started_at: string;
  active_connections: number;
};

type ComputeActiveJob = {
  id: string;
  user_id: string;
  username: string;
  required_hashrate_ths: number;
  required_work_th: number;
  hashrate_tolerance_percent: number;
  proof_window_seconds: number;
  max_proof_attempts: number;
  valid_work_th: number;
  valid_worker_count: number;
  started_at: string;
};

type ComputeWorker = {
  id: string;
  worker_name: string;
  status: string;
  runtime_connections: number;
  conflict: boolean;
  reported_hashrate_ths?: number;
  connection_count: number;
  valid_shares: number;
  invalid_shares: number;
  valid_work_th: number;
  last_seen_at?: string;
  last_connected_at?: string;
  last_disconnected_at?: string;
  stats_reset_at?: string;
  last_ip?: string;
  last_error?: string;
};

type ComputeShare = {
  id: string;
  pow_job_id: string;
  worker_name: string;
  share_hash: string;
  share_target: string;
  work_th: number;
  is_valid: boolean;
  rejection_reason?: string;
  submitted_at: string;
};

type ComputeStatusResponse = {
  policy: ComputePolicy;
  runtime: ComputeRuntime;
  active_job?: ComputeActiveJob;
  workers: ComputeWorker[];
  recent_shares: ComputeShare[];
};

type AuditEvent = {
  id: string;
  event_type: string;
  target_type?: string;
  target_id?: string;
  severity: string;
  ip_address?: string;
  details: Record<string, unknown>;
  created_at: string;
};

type AuditEventsResponse = {
  events: AuditEvent[];
  limit: number;
  offset: number;
  file_activity_count: number;
};

type AuditCleanupPolicy = {
  retention_days: number;
  allow_clear_all: boolean;
  backup_required: boolean;
  restore_requires_checksum: boolean;
  backup_storage: string;
  protected_cleanup_events: boolean;
};

type AuditSettingsResponse = {
  policy: AuditCleanupPolicy;
};

type AuditBackup = {
  id: string;
  backup_type: string;
  checksum_sha256: string;
  file_name: string;
  event_count: number;
  created_at: string;
  restored_at?: string;
};

type AuditBackupsResponse = {
  backups: AuditBackup[];
};

type RestoreResponse = {
  backup_id: string;
  checksum_sha256: string;
  restored_events: number;
};

const AUTH_SESSION_INVALID_EVENT = "archivon:auth-session-invalid";
const PUBLIC_PATH_PREFIX = publicPathPrefix();

const api = {
  async get<T>(path: string): Promise<T> {
    const response = await fetch(appPath(path), { credentials: "include", cache: "no-store" });
    return parseResponse<T>(response);
  },
  async post<T>(path: string, body?: unknown): Promise<T> {
    const response = await fetch(appPath(path), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return parseResponse<T>(response);
  },
  async patch<T>(path: string, body?: unknown): Promise<T> {
    const response = await fetch(appPath(path), {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return parseResponse<T>(response);
  },
  async delete<T>(path: string): Promise<T> {
    const response = await fetch(appPath(path), {
      method: "DELETE",
      credentials: "include"
    });
    return parseResponse<T>(response);
  },
  async postForm<T>(path: string, body: FormData): Promise<T> {
    const response = await fetch(appPath(path), {
      method: "POST",
      credentials: "include",
      body
    });
    return parseResponse<T>(response);
  },
  async postFormWithProgress<T>(path: string, body: FormData, onProgress: (loaded: number, total: number) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open("POST", appPath(path));
      request.withCredentials = true;
      request.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          onProgress(event.loaded, event.total);
        }
      };
      request.onerror = () => reject(new Error("network_error"));
      request.onabort = () => reject(new Error("request_aborted"));
      request.onload = () => {
        let payload: Record<string, unknown> = {};
        try {
          payload = request.responseText ? JSON.parse(request.responseText) : {};
        } catch {
          payload = {};
        }
        if (request.status < 200 || request.status >= 300) {
          const error = typeof payload.error === "string" ? payload.error : "request_failed";
          if (request.status === 401 && error === "not_authenticated") {
            window.dispatchEvent(new CustomEvent(AUTH_SESSION_INVALID_EVENT));
          }
          reject(new Error(error));
          return;
        }
        resolve(payload as T);
      };
      request.send(body);
    });
  },
  async postRaw<T>(path: string, raw: string): Promise<T> {
    const response = await fetch(appPath(path), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: raw
    });
    return parseResponse<T>(response);
  }
};

function publicPathPrefix() {
  const configured = (window.__ARCHIVON_PUBLIC_PATH__ ?? "").trim();
  if (configured === "" || configured === "/") {
    return "";
  }
  const normalized = configured.replace(/^\/+/, "").replace(/\/+$/, "");
  return normalized === "" ? "" : `/${normalized}`;
}

function appPath(path: string) {
  if (!path.startsWith("/") || PUBLIC_PATH_PREFIX === "") {
    return path;
  }
  return `${PUBLIC_PATH_PREFIX}${path}`;
}

async function parseResponse<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = typeof payload.error === "string" ? payload.error : "request_failed";
    if (response.status === 401 && error === "not_authenticated") {
      window.dispatchEvent(new CustomEvent(AUTH_SESSION_INVALID_EVENT));
    }
    throw new Error(error);
  }
  return payload as T;
}

function App() {
  const [bootstrap, setBootstrap] = useState<BootstrapStatus | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [kms, setKms] = useState<KMSStatus | null>(null);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [authSettings, setAuthSettings] = useState<AuthSettingsResponse | null>(null);
  const [folders, setFolders] = useState<ProtectedFolder[]>([]);
  const [selectedFolderID, setSelectedFolderID] = useState("");
  const [files, setFiles] = useState<ProtectedFile[]>([]);
  const [permissions, setPermissions] = useState<FolderPermission[]>([]);
  const [clientFolders, setClientFolders] = useState<ClientFolder[]>([]);
  const [selectedClientFolderID, setSelectedClientFolderID] = useState("");
  const [clientFiles, setClientFiles] = useState<ClientFile[]>([]);
  const [accessSettings, setAccessSettings] = useState<AccessSettingsResponse | null>(null);
  const [adminQueue, setAdminQueue] = useState<QueueResponse | null>(null);
  const [computeStatus, setComputeStatus] = useState<ComputeStatusResponse | null>(null);
  const [auditSettings, setAuditSettings] = useState<AuditSettingsResponse | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEventsResponse | null>(null);
  const [auditBackups, setAuditBackups] = useState<AuditBackupsResponse | null>(null);
  const [accessJobs, setAccessJobs] = useState<ClientPowJob[]>([]);
  const [accessSessions, setAccessSessions] = useState<AccessSession[]>([]);
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [clientNodeLinkOK, setClientNodeLinkOK] = useState(false);
  const [storageUploadProgress, setStorageUploadProgress] = useState<UploadProgress | null>(null);
  const [adminDAVSession, setAdminDAVSession] = useState<AdminDAVCredentials | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [secret, setSecret] = useState<{ title: string; value: string } | null>(null);
  const [activeAdminSection, setActiveAdminSection] = useState<AdminSection>("storage");
  const currentUserRef = useRef<User | null>(null);
  const nodeLinkRequestSeqRef = useRef(0);

  const canAdminister = currentUser?.role === "super_admin" || currentUser?.role === "admin";
  const storageAvailable = (kms ?? status?.kms)?.available === true;
  const selectedFolder = folders.find((folder) => folder.id === selectedFolderID) ?? null;
  const clientUsers = useMemo(() => users.filter((user) => user.role === "client" && !user.is_blocked), [users]);
  const selectedClientFolder = clientFolders.find((folder) => folder.id === selectedClientFolderID) ?? null;
  const isClientWorkspace = currentUser?.role === "client" && !currentUser.must_change_password;
  const isAdminWorkspace = canAdminister && !currentUser?.must_change_password;
  const isAuthWorkspace = !currentUser || currentUser.must_change_password;
  const shellClassName = [
    "app-shell",
    isClientWorkspace || isAdminWorkspace || isAuthWorkspace ? "app-shell-client" : "",
    isClientWorkspace ? "app-shell-user" : "",
    isAdminWorkspace ? "app-shell-admin" : "",
    isAuthWorkspace ? "app-shell-auth" : ""
  ].filter(Boolean).join(" ");
  const activeClientSession = selectedClientFolder ? accessSessions.find((session) => session.folder_id === selectedClientFolder.id && session.status === "active") : undefined;
  const activeClientSessionsKey = useMemo(() => (
    accessSessions
      .filter((session) => session.status === "active" && new Date(session.expires_at).getTime() > Date.now())
      .map((session) => `${session.folder_id}:${session.id}:${session.expires_at}`)
      .sort()
      .join("|")
  ), [accessSessions]);
  const activeAccessCount = (adminQueue?.jobs.filter((job) => job.status === "queued" || job.status === "running").length ?? 0) + (adminQueue?.active_sessions.length ?? 0);
  const connectedWorkerCount = computeStatus?.workers.filter((worker) => worker.runtime_connections > 0).length ?? 0;
  const availableRoles = useMemo<Role[]>(() => {
    if (currentUser?.role === "super_admin") {
      return ["admin", "client"];
    }
    if (currentUser?.role === "admin") {
      return ["client"];
    }
    return ["client"];
  }, [currentUser?.role]);

  function clearSessionState(messageText = "") {
    setCurrentUser(null);
    setUsers([]);
    setAuthSettings(null);
    setFolders([]);
    setSelectedFolderID("");
    setFiles([]);
    setPermissions([]);
    setClientFolders([]);
    setSelectedClientFolderID("");
    setClientFiles([]);
    setAccessSettings(null);
    setAdminQueue(null);
    setComputeStatus(null);
    setAuditSettings(null);
    setAuditEvents(null);
    setAuditBackups(null);
    setKms(null);
    setAccessJobs([]);
    setAccessSessions([]);
    setTerminalLines([]);
    nodeLinkRequestSeqRef.current += 1;
    setClientNodeLinkOK(false);
    setAdminDAVSession(null);
    setSecret(null);
    setActiveAdminSection("storage");
    if (messageText) {
      setMessage(messageText);
    }
  }

  async function refreshStatus() {
    const [bootstrapStatus, systemStatus] = await Promise.all([
      api.get<BootstrapStatus>("/api/bootstrap/status"),
      api.get<SystemStatus>("/system/status")
    ]);
    setBootstrap(bootstrapStatus);
    setStatus(systemStatus);
  }

  async function refreshSession() {
    try {
      const response = await api.get<AuthResponse>("/api/auth/me");
      setCurrentUser(response.user);
    } catch {
      clearSessionState();
    }
  }

  async function refreshUsers() {
    if (!canAdminister || currentUser?.must_change_password) {
      setUsers([]);
      setAuthSettings(null);
      setPermissions([]);
      setAccessSettings(null);
      setAdminQueue(null);
      setComputeStatus(null);
      setAuditSettings(null);
      setAuditEvents(null);
      setAuditBackups(null);
      return;
    }
    const response = await api.get<UsersResponse>("/api/admin/users");
    setUsers(response.users);
  }

  async function refreshAuthSettings() {
    if (!canAdminister || currentUser?.must_change_password) {
      setAuthSettings(null);
      return;
    }
    const response = await api.get<AuthSettingsResponse>("/api/admin/auth/settings");
    setAuthSettings(response);
  }

  async function refreshKms() {
    if (!canAdminister || currentUser?.must_change_password) {
      setKms(null);
      return;
    }
    const response = await api.get<KMSStatus>("/api/kms/status");
    setKms(response);
  }

  async function refreshFolders(options: { autoSelect?: boolean } = {}) {
    if (!canAdminister || currentUser?.must_change_password) {
      setFolders([]);
      setSelectedFolderID("");
      setFiles([]);
      setPermissions([]);
      return;
    }
    const response = await api.get<FoldersResponse>("/api/admin/folders");
    const autoSelect = options.autoSelect ?? true;
    setFolders(response.folders);
    setSelectedFolderID((current) => {
      if (current && response.folders.some((folder) => folder.id === current)) {
        return current;
      }
      return autoSelect ? response.folders[0]?.id ?? "" : "";
    });
  }

  async function refreshFiles(folderID = selectedFolderID) {
    if (!canAdminister || currentUser?.must_change_password || !folderID) {
      setFiles([]);
      return;
    }
    const response = await api.get<FilesResponse>(`/api/admin/folders/${folderID}/files`);
    setFiles(response.files);
  }

  async function refreshPermissions(folderID = selectedFolderID) {
    if (!canAdminister || currentUser?.must_change_password || !folderID) {
      setPermissions([]);
      return;
    }
    const response = await api.get<PermissionsResponse>(`/api/admin/folders/${folderID}/permissions`);
    setPermissions(response.permissions);
  }

  async function refreshClientFolders() {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      setClientFolders([]);
      setSelectedClientFolderID("");
      setClientFiles([]);
      setAccessJobs([]);
      setAccessSessions([]);
      setTerminalLines([]);
      nodeLinkRequestSeqRef.current += 1;
      setClientNodeLinkOK(false);
      return;
    }
    const response = await api.get<ClientFoldersResponse>("/api/client/folders");
    setClientFolders(response.folders);
    setSelectedClientFolderID((current) => {
      if (current && response.folders.some((folder) => folder.id === current)) {
        return current;
      }
      return response.folders[0]?.id ?? "";
    });
  }

  async function refreshClientFiles(folderID = selectedClientFolderID) {
    if (currentUser?.role !== "client" || currentUser.must_change_password || !folderID) {
      setClientFiles([]);
      return;
    }
    const folder = clientFolders.find((item) => item.id === folderID);
    if (folder?.access && !folder.access.can_unlock_and_access) {
      setClientFiles([]);
      return;
    }
    const hasOpenSession = accessSessions.some((session) => (
      session.folder_id === folderID &&
      session.status === "active" &&
      new Date(session.expires_at).getTime() > Date.now()
    ));
    if (!hasOpenSession) {
      setClientFiles([]);
      return;
    }
    const response = await api.get<ClientFilesResponse>(`/api/client/folders/${folderID}/files`);
    setClientFiles(response.files);
  }

  async function refreshAccessSettings() {
    if (!canAdminister || currentUser?.must_change_password) {
      setAccessSettings(null);
      setAdminQueue(null);
      return;
    }
    const [settings, queue] = await Promise.all([
      api.get<AccessSettingsResponse>("/api/admin/access/settings"),
      api.get<QueueResponse>("/api/admin/access/queue")
    ]);
    setAccessSettings(settings);
    setAdminQueue(queue);
  }

  async function refreshComputeStatus() {
    if (!canAdminister || currentUser?.must_change_password) {
      setComputeStatus(null);
      return;
    }
    const response = await api.get<ComputeStatusResponse>("/api/admin/compute/status");
    setComputeStatus(response);
  }

  async function refreshAudit() {
    if (!canAdminister || currentUser?.must_change_password) {
      setAuditSettings(null);
      setAuditEvents(null);
      setAuditBackups(null);
      return;
    }
    const [settings, events, backups] = await Promise.all([
      api.get<AuditSettingsResponse>("/api/admin/audit/settings"),
      api.get<AuditEventsResponse>("/api/admin/audit/events?limit=30"),
      api.get<AuditBackupsResponse>("/api/admin/audit/cleanup/backups")
    ]);
    setAuditSettings(settings);
    setAuditEvents(events);
    setAuditBackups(backups);
  }

  async function refreshClientAccess() {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      setAccessJobs([]);
      setAccessSessions([]);
      setTerminalLines([]);
      nodeLinkRequestSeqRef.current += 1;
      setClientNodeLinkOK(false);
      return;
    }
    const [jobs, sessions] = await Promise.all([
      api.get<ClientJobsResponse>("/api/client/access/jobs"),
      api.get<SessionsResponse>("/api/client/access/sessions")
    ]);
    setAccessJobs(jobs.jobs);
    setAccessSessions(sessions.sessions);
    const selectedSessionIsOpen = selectedClientFolderID !== "" && sessions.sessions.some((session) => (
      session.folder_id === selectedClientFolderID &&
      session.status === "active" &&
      new Date(session.expires_at).getTime() > Date.now()
    ));
    if (!selectedSessionIsOpen) {
      setClientFiles([]);
    }
  }

  async function refreshClientNodeLink() {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      nodeLinkRequestSeqRef.current += 1;
      setClientNodeLinkOK(false);
      return;
    }
    const requestSeq = nodeLinkRequestSeqRef.current + 1;
    nodeLinkRequestSeqRef.current = requestSeq;
    try {
      const response = await api.get<NodeLinkResponse>("/api/client/access/node-link");
      if (nodeLinkRequestSeqRef.current === requestSeq) {
        setClientNodeLinkOK(response.node_link_ok === true);
      }
    } catch (error) {
      if (nodeLinkRequestSeqRef.current === requestSeq) {
        setClientNodeLinkOK(false);
      }
      throw error;
    }
  }

  async function refreshClientTerminal(folderID = selectedClientFolderID) {
    if (currentUser?.role !== "client" || currentUser.must_change_password || !folderID) {
      setTerminalLines([]);
      return;
    }
    const folder = clientFolders.find((item) => item.id === folderID);
    if (folder?.access && !folder.access.can_unlock_and_access) {
      setTerminalLines([]);
      return;
    }
    const response = await api.get<TerminalResponse>(`/api/client/access/terminal?folder_id=${encodeURIComponent(folderID)}`);
    setTerminalLines(response.lines);
  }

  async function downloadClientFile(file: ClientFile) {
    const response = await fetch(appPath(`/api/client/files/${file.id}/download`), { credentials: "include" });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      const error = typeof payload.error === "string" ? payload.error : "download_failed";
      throw new Error(error);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = file.name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  async function downloadAdminJSON(path: string, fallbackName: string, body?: unknown) {
    const response = await fetch(appPath(path), {
      method: body === undefined ? "GET" : "POST",
      credentials: "include",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      const error = typeof payload.error === "string" ? payload.error : "download_failed";
      throw new Error(error);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const match = disposition.match(/filename="([^"]+)"/);
    const anchor = document.createElement("a");
    const url = URL.createObjectURL(blob);
    anchor.href = url;
    anchor.download = match?.[1] ?? fallbackName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  useEffect(() => {
    void (async () => {
      try {
        await refreshStatus();
        await refreshSession();
      } catch (error) {
        setMessage(errorMessage(error));
      }
    })();
  }, []);

  useEffect(() => {
    currentUserRef.current = currentUser;
  }, [currentUser]);

  useEffect(() => {
    const handleInvalidSession = () => {
      if (!currentUserRef.current) {
        return;
      }
      clearSessionState("Session ended. Sign in again");
    };
    window.addEventListener(AUTH_SESSION_INVALID_EVENT, handleInvalidSession);
    return () => window.removeEventListener(AUTH_SESSION_INVALID_EVENT, handleInvalidSession);
  }, []);

  useEffect(() => {
    void refreshUsers().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshAuthSettings().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshKms().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshFolders().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshFiles().catch((error) => setMessage(errorMessage(error)));
  }, [selectedFolderID]);

  useEffect(() => {
    void refreshPermissions().catch((error) => setMessage(errorMessage(error)));
  }, [selectedFolderID, currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshClientFolders().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      return;
    }
    void refreshClientFolders().catch((error) => setMessage(errorMessage(error)));
  }, [activeClientSessionsKey]);

  useEffect(() => {
    void refreshClientFiles().catch((error) => setMessage(errorMessage(error)));
  }, [selectedClientFolderID, clientFolders.length, activeClientSession?.id, activeClientSession?.expires_at]);

  useEffect(() => {
    void refreshAccessSettings().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshComputeStatus().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshAudit().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshClientAccess().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshClientNodeLink().catch((error) => setMessage(errorMessage(error)));
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    void refreshClientTerminal().catch((error) => setMessage(errorMessage(error)));
  }, [selectedClientFolderID, clientFolders.length, currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshClientNodeLink().catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password]);

  useEffect(() => {
    if (currentUser?.role !== "client" || currentUser.must_change_password || !selectedClientFolderID) {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshClientAccess().catch(() => undefined);
      void refreshClientTerminal().catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password, selectedClientFolderID, clientFolders.length]);

  useEffect(() => {
    if (!currentUser || currentUser.must_change_password) {
      return;
    }
    const timer = window.setInterval(() => {
      if (currentUser.role === "client") {
        void refreshClientAccess().catch(() => undefined);
        void refreshClientFiles().catch(() => undefined);
      }
      if (canAdminister) {
        void refreshAccessSettings().catch(() => undefined);
        void refreshComputeStatus().catch(() => undefined);
      }
    }, 5000);
    return () => window.clearInterval(timer);
  }, [currentUser?.id, currentUser?.role, currentUser?.must_change_password, selectedClientFolderID, activeClientSession?.id, activeClientSession?.expires_at, canAdminister]);

  useEffect(() => {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      return;
    }
    const root = document.querySelector(".app-shell-client");
    root?.querySelectorAll<HTMLElement>("[data-tooltip]").forEach((element) => {
      const tooltip = element.dataset.tooltip;
      if (tooltip) {
        element.setAttribute("title", tooltip);
      }
    });
  }, [
    currentUser?.id,
    currentUser?.role,
    currentUser?.must_change_password,
    selectedClientFolderID,
    clientFolders,
    clientFiles,
    accessJobs,
    accessSessions,
    terminalLines,
    clientNodeLinkOK
  ]);

  useEffect(() => {
    if (currentUser?.role !== "client" || currentUser.must_change_password) {
      return;
    }
    const flashTarget = (target: HTMLElement) => {
      if (target.hasAttribute("disabled") || target.getAttribute("aria-disabled") === "true") {
        return;
      }
      target.classList.remove("is-click-flashing");
      void target.offsetWidth;
      target.classList.add("is-click-flashing");
    };
    const handleClick = (event: MouseEvent) => {
      if (!(event.target instanceof Element)) {
        return;
      }
      const target = event.target.closest(".app-shell-client button:not(.folder-row)");
      if (target instanceof HTMLElement) {
        flashTarget(target);
      }
    };
    const handleAnimationEnd = (event: AnimationEvent) => {
      if (event.animationName === "command-text-double-flash" && event.target instanceof HTMLElement) {
        event.target.classList.remove("is-click-flashing");
      }
    };
    document.addEventListener("click", handleClick);
    document.addEventListener("animationend", handleAnimationEnd);
    return () => {
      document.removeEventListener("click", handleClick);
      document.removeEventListener("animationend", handleAnimationEnd);
    };
  }, [currentUser?.role, currentUser?.must_change_password]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setMessage("");
    try {
      await action();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const handleLogout = () =>
    run(async () => {
      await api.post("/api/auth/logout");
      clearSessionState("Session closed");
    });

  return (
    <main className={shellClassName}>
      <header className="topbar">
        <div>
          <p className="eyebrow">Archivon</p>
          <div className="client-title-row">
            <h1>Archivon</h1>
            {isClientWorkspace && currentUser && !currentUser.must_change_password && (
              <ClientVersionFooter status={status} />
            )}
          </div>
        </div>
        {isClientWorkspace && currentUser && !currentUser.must_change_password ? (
          <ClientTopbarLogout busy={busy} onLogout={handleLogout} />
        ) : (
          <SystemBadge status={status} />
        )}
      </header>

      {message && <div className="notice notice-error">{message}</div>}
      {secret && (
        <div className="notice notice-secret">
          <span>{secret.title}</span>
          <code>{secret.value}</code>
          <button type="button" onClick={() => setSecret(null)}>Hide</button>
        </div>
      )}

      <section className="layout">
        {!isAuthWorkspace && (
          <aside className="side-panel">
            {!isClientWorkspace && <StatusPanel bootstrap={bootstrap} status={status} />}
            {currentUser && !currentUser.must_change_password && canAdminister && (
              <KmsPanel kms={kms ?? status?.kms ?? null} />
            )}
            {currentUser && (
              <SessionPanel
                user={currentUser}
                busy={busy}
                showLogout={!isClientWorkspace}
                onLogout={handleLogout}
              />
            )}
            {isClientWorkspace && (
              <ClientSessionInfoPanel
                selectedFolder={selectedClientFolder}
                activeSession={activeClientSession}
              />
            )}
          </aside>
        )}

        <section className="work-panel">
          {!currentUser && bootstrap?.required && (
            <BootstrapForm
              busy={busy}
              minPasswordLength={bootstrap.min_password_length}
              onCreate={(payload) =>
                run(async () => {
                  await api.post<AuthResponse>("/api/bootstrap/super-admin", payload);
                  await refreshStatus();
                  setMessage("Super administrator created. Now sign in with this account.");
                })
              }
            />
          )}

          {!currentUser && !bootstrap?.required && (
            <LoginForm
              busy={busy}
              onLogin={(payload) =>
                run(async () => {
                  const response = await api.post<AuthResponse>("/api/auth/login", payload);
                  setCurrentUser(response.user);
                  setSecret(null);
                  await refreshStatus();
                })
              }
            />
          )}

          {currentUser?.must_change_password && (
            <PasswordChangeForm
              busy={busy}
              forced
              onChangePassword={(payload) =>
                run(async () => {
                  const response = await api.post<AuthResponse>("/api/auth/change-password", payload);
                  setCurrentUser(response.user);
                  setMessage("Password changed");
                  await refreshUsers();
                  await refreshKms();
                  await refreshFolders();
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && (
            <AdminWorkspaceNav
              active={activeAdminSection}
              counts={{
                storage: folders.length,
                users: users.length,
                access: activeAccessCount,
                compute: connectedWorkerCount,
                audit: auditEvents?.events.length ?? 0
              }}
              onSelect={setActiveAdminSection}
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && activeAdminSection === "storage" && (
            <StoragePanel
              busy={busy}
              storageAvailable={storageAvailable}
              folders={folders}
              selectedFolder={selectedFolder}
              defaultPoWPolicy={accessSettings?.policy ?? null}
              files={files}
              clientUsers={clientUsers}
              permissions={permissions}
              uploadProgress={storageUploadProgress}
              adminDAVSession={adminDAVSession}
              onSelectFolder={(folderID) => {
                setSelectedFolderID(folderID);
                setStorageUploadProgress(null);
                setAdminDAVSession(null);
              }}
              onClearUploadProgress={() => setStorageUploadProgress(null)}
              onCreateFolder={(payload) =>
                run(async () => {
                  const response = await api.post<CreateFolderResponse>("/api/admin/folders", payload);
                  setSelectedFolderID(response.folder.id);
                  await refreshFolders();
                  await refreshFiles(response.folder.id);
                  await refreshPermissions(response.folder.id);
                  setMessage("Protected folder created");
                })
              }
              onDeleteFolder={(folderID) =>
                run(async () => {
                  const response = await api.delete<DeleteFolderResponse>(`/api/admin/folders/${folderID}`);
                  if (selectedFolderID === response.deleted_folder_id) {
                    setSelectedFolderID("");
                    setFiles([]);
                    setPermissions([]);
                    setAdminDAVSession(null);
                  }
                  await refreshFolders({ autoSelect: false });
                  setMessage(`Folder deleted, files: ${response.deleted_files}`);
                })
              }
              onUploadFiles={(folderID, uploadFiles) =>
                run(async () => {
                  setStorageUploadProgress({
                    status: "running",
                    total: uploadFiles.length,
                    completed: 0,
                    current_file: uploadFiles[0] ? uploadDisplayPath(uploadFiles[0]) : "",
                    current_loaded: 0,
                    current_total: uploadFiles[0]?.size ?? 0
                  });
                  try {
                    for (const [index, file] of uploadFiles.entries()) {
                      const relativePath = uploadRelativePath(file);
                      const displayPath = uploadDisplayPath(file);
                      setStorageUploadProgress({
                        status: "running",
                        total: uploadFiles.length,
                        completed: index,
                        current_file: displayPath,
                        current_loaded: 0,
                        current_total: file.size
                      });
                      const form = new FormData();
                      form.append("file", file, file.name);
                      if (relativePath) {
                        form.append("relative_path", relativePath);
                      }
                      await api.postFormWithProgress<UploadFileResponse>(
                        `/api/admin/folders/${folderID}/files`,
                        form,
                        (loaded, total) => setStorageUploadProgress({
                          status: "running",
                          total: uploadFiles.length,
                          completed: index,
                          current_file: displayPath,
                          current_loaded: loaded,
                          current_total: total
                        })
                      );
                      setStorageUploadProgress({
                        status: "running",
                        total: uploadFiles.length,
                        completed: index + 1,
                        current_file: displayPath,
                        current_loaded: file.size,
                        current_total: file.size
                      });
                    }
                    setStorageUploadProgress({
                      status: "done",
                      total: uploadFiles.length,
                      completed: uploadFiles.length,
                      current_file: ""
                    });
                  } catch (error) {
                    const message = errorMessage(error);
                    setStorageUploadProgress((current) => current ? { ...current, status: "error", error_message: message } : current);
                    throw error;
                  }
                  await refreshFolders();
                  await refreshFiles(folderID);
                  setMessage(uploadFiles.length === 1 ? "File added to the protected folder" : `Files added to the protected folder: ${formatFileCount(uploadFiles.length)}`);
                })
              }
              onExportFolderBackup={(folderID, folderName) =>
                run(async () => {
                  await downloadAdminJSON(`/api/admin/folders/${folderID}/backup`, `${folderName || "archivon-folder"}.archivon-backup.zip`);
                  setMessage("Folder backup downloaded");
                })
              }
              onImportFolderBackup={(backupFile) =>
                run(async () => {
                  const form = new FormData();
                  form.append("file", backupFile, backupFile.name);
                  const response = await api.postForm<ImportFolderBackupResponse>("/api/admin/folder-backups", form);
                  setSelectedFolderID(response.folder.id);
                  setAdminDAVSession(null);
                  await refreshFolders();
                  await refreshFiles(response.folder.id);
                  await refreshPermissions(response.folder.id);
                  setMessage(`Backup imported: ${response.folder.name}, files: ${formatFileCount(response.imported_files)}`);
                })
              }
              onCreateAdminDAVSession={(folderID) =>
                run(async () => {
                  const response = await api.post<AdminDAVSessionResponse>(`/api/admin/folders/${folderID}/admin-dav`);
                  setAdminDAVSession(response.session);
                  setMessage("Admin WebDAV access created");
                })
              }
              onDeleteFile={(fileID) =>
                run(async () => {
                  const response = await api.delete<DeleteFileResponse>(`/api/admin/files/${fileID}`);
                  await refreshFolders();
                  await refreshFiles(response.folder_id);
                  setMessage("File deleted without opening the folder");
                })
              }
              onSetPermission={(folderID, userID, access) =>
                run(async () => {
                  await api.post<UpdatePermissionResponse>(`/api/admin/folders/${folderID}/permissions`, {
                    user_id: userID,
                    ...access
                  });
                  await refreshPermissions(folderID);
                  setMessage("Folder permissions updated");
                })
              }
              onRefresh={() =>
                run(async () => {
                  await refreshFolders();
                  await refreshFiles();
                  await refreshPermissions();
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && activeAdminSection === "users" && (
            <AdminPanel
              busy={busy}
              currentUser={currentUser}
              users={users}
              authSettings={authSettings}
              availableRoles={availableRoles}
              onSaveAuthSettings={(authTTLHours) =>
                run(async () => {
                  await api.post<AuthSettingsResponse>("/api/admin/auth/settings", { auth_ttl_hours: authTTLHours });
                  await refreshAuthSettings();
                  setMessage("Login TTL updated");
                })
              }
              onCreateUser={(payload) =>
                run(async () => {
                  const response = await api.post<CreateUserResponse>("/api/admin/users", payload);
                  setSecret({ title: `Temporary password for ${response.user.username}`, value: response.temporary_password });
                  await refreshUsers();
                  await refreshKms();
                  await refreshFolders();
                  await refreshPermissions();
                })
              }
              onResetPassword={(user) =>
                run(async () => {
                  const response = await api.patch<CreateUserResponse>(`/api/admin/users/${user.id}/password`);
                  setSecret({ title: `New temporary password for ${response.user.username}`, value: response.temporary_password });
                  await refreshUsers();
                  await refreshKms();
                  await refreshFolders();
                  await refreshPermissions();
                })
              }
              onSetBlocked={(user, blocked) =>
                run(async () => {
                  await api.patch<AuthResponse>(`/api/admin/users/${user.id}/status`, { blocked });
                  await refreshUsers();
                  await refreshKms();
                  await refreshFolders();
                  await refreshPermissions();
                })
              }
              onDeleteUser={(user) =>
                run(async () => {
                  const response = await api.delete<DeleteUserResponse>(`/api/admin/users/${user.id}`);
                  await refreshUsers();
                  await refreshFolders();
                  await refreshPermissions();
                  await refreshAccessSettings();
                  setMessage(`User deleted: ${response.username}`);
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && activeAdminSection === "access" && (
            <AccessAdminPanel
              busy={busy}
              currentUser={currentUser}
              settings={accessSettings}
              queue={adminQueue}
              computeStatus={computeStatus}
              onSave={(policy) =>
                run(async () => {
                  await api.post<AccessSettingsResponse>("/api/admin/access/settings", policy);
                  await refreshAccessSettings();
                  setMessage("PoW settings updated");
                })
              }
              onRefresh={() =>
                run(async () => {
                  await refreshAccessSettings();
                })
              }
              onCloseSession={(sessionID) =>
                run(async () => {
                  await api.post<SessionResponse>(`/api/admin/access/sessions/${sessionID}/close`);
                  await refreshAccessSettings();
                  await refreshClientAccess();
                  setMessage("Active session closed by administrator");
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && activeAdminSection === "compute" && (
            <ComputeAdminPanel
              busy={busy}
              currentUser={currentUser}
              status={computeStatus}
              onSave={(payload) =>
                run(async () => {
                  await api.post<ComputeStatusResponse>("/api/admin/compute/settings", payload);
                  await refreshComputeStatus();
                  setMessage("Compute gateway settings updated");
                })
              }
              onRefresh={() =>
                run(async () => {
                  await refreshComputeStatus();
                  await refreshAccessSettings();
                })
              }
              onResetWorker={(workerID) =>
                run(async () => {
                  await api.post<ComputeStatusResponse>(`/api/admin/compute/workers/${workerID}/reset-stats`);
                  await refreshComputeStatus();
                  setMessage("Worker statistics reset");
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && canAdminister && activeAdminSection === "audit" && (
            <AuditAdminPanel
              busy={busy}
              settings={auditSettings}
              events={auditEvents}
              backups={auditBackups}
              onSavePolicy={(retentionDays) =>
                run(async () => {
                  await api.post<AuditSettingsResponse>("/api/admin/audit/settings", { retention_days: retentionDays });
                  await refreshAudit();
                  setMessage("Audit settings updated");
                })
              }
              onExport={(fileRelated) =>
                run(async () => {
                  await downloadAdminJSON(`/api/admin/audit/export?file_related=${fileRelated ? "true" : "false"}`, "archivon-audit-export.json");
                  await refreshAudit();
                  setMessage("Audit export downloaded");
                })
              }
              onCleanup={(olderThanDays) =>
                run(async () => {
                  await downloadAdminJSON("/api/admin/audit/cleanup/file-activity", "archivon-file-activity-backup.json", { older_than_days: olderThanDays });
                  await refreshAudit();
                  setMessage("File-related audit log cleaned; backup downloaded");
                })
              }
              onRestore={(file) =>
                run(async () => {
                  const raw = await file.text();
                  const response = await api.postRaw<RestoreResponse>("/api/admin/audit/cleanup/restore", raw);
                  await refreshAudit();
                  setMessage(`Backup restored: ${response.restored_events}`);
                })
              }
              onRefresh={() =>
                run(async () => {
                  await refreshAudit();
                })
              }
            />
          )}

          {currentUser && !currentUser.must_change_password && currentUser.role === "client" && (
            <>
              <ClientPanel
                busy={busy}
                folders={clientFolders}
                selectedFolder={selectedClientFolder}
                files={clientFiles}
                jobs={accessJobs}
                sessions={accessSessions}
                terminalLines={terminalLines}
                nodeLinkOK={clientNodeLinkOK}
                onSelectFolder={(folderID) => {
                  setSelectedClientFolderID(folderID);
                  setClientFiles([]);
                }}
                onBlockedByActiveSession={(session) => {
                  const folder = clientFolders.find((item) => item.id === session.folder_id);
                  setMessage(folder ? `Close the session first: ${folder.name}` : "Close the session first");
                }}
                onRequestAccess={(folderID) =>
                  run(async () => {
                    await api.post<ClientJobResponse>("/api/client/access/jobs", { folder_id: folderID });
                    await refreshClientAccess();
                    await refreshClientNodeLink();
                    await refreshClientTerminal(folderID);
                    setMessage("Verification running");
                  })
                }
                onCancelJob={(jobID) =>
                  run(async () => {
                    await api.post<ClientJobResponse>(`/api/client/access/jobs/${jobID}/cancel`);
                    await refreshClientAccess();
                    await refreshClientNodeLink();
                    await refreshClientTerminal();
                    setMessage("Closed");
                  })
                }
                onCloseSession={(sessionID) =>
                  run(async () => {
                    await api.post(`/api/client/access/sessions/${sessionID}/close`);
                    setClientFiles([]);
                    await refreshClientAccess();
                    await refreshClientNodeLink();
                    await refreshClientTerminal();
                    setMessage("Access session closed");
                  })
                }
                onDownloadFile={(file) =>
                  run(async () => {
                    await downloadClientFile(file);
                    setMessage("File downloaded");
                  })
                }
                onRefresh={() =>
                  run(async () => {
                    await refreshClientFolders();
                    await refreshClientFiles();
                    await refreshClientAccess();
                    await refreshClientNodeLink();
                    await refreshClientTerminal();
                  })
                }
              />
            </>
          )}
        </section>
      </section>
    </main>
  );
}

function AdminWorkspaceNav({
  active,
  counts,
  onSelect
}: {
  active: AdminSection;
  counts: Record<AdminSection, number>;
  onSelect: (section: AdminSection) => void;
}) {
  const items: Array<{ id: AdminSection; label: string; tooltip: string }> = [
    { id: "storage", label: "Storage", tooltip: "Folders, files, client permissions, and per-folder policy." },
    { id: "users", label: "Accounts", tooltip: "Users, roles, temporary passwords, blocks, and login TTL." },
    { id: "access", label: "Access", tooltip: "PoW template for new folders, access queue, and active TTL sessions." },
    { id: "compute", label: "Compute", tooltip: "Embedded compute gateway, worker names, and recent shares." },
    { id: "audit", label: "Audit Log", tooltip: "Events, export, file-activity cleanup, and backup restore." }
  ];
  return (
    <nav className="workspace-nav" aria-label="Administrator sections">
      {items.map((item) => (
        <button
          type="button"
          key={item.id}
          className={active === item.id ? "workspace-tab active has-tooltip" : "workspace-tab has-tooltip"}
          data-tooltip={item.tooltip}
          title={item.tooltip}
          aria-pressed={active === item.id}
          onClick={() => onSelect(item.id)}
        >
          <span>{item.label}</span>
          <b>{counts[item.id]}</b>
        </button>
      ))}
    </nav>
  );
}

function BootstrapForm({
  busy,
  minPasswordLength,
  onCreate
}: {
  busy: boolean;
  minPasswordLength: number;
  onCreate: (payload: { username: string; password: string; description: string }) => void;
}) {
  const [username, setUsername] = useState("superadmin");
  const [password, setPassword] = useState("");
  const [description, setDescription] = useState("Initial deployment account");

  return (
    <form className="card form-grid auth-card" onSubmit={(event) => submit(event, () => onCreate({ username, password, description }))}>
      <h2>Initial Setup</h2>
      <label>
        Username
        <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
      </label>
      <label>
        Password
        <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" minLength={minPasswordLength} autoComplete="new-password" />
      </label>
      <label>
        Description
        <input value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      <button type="submit" disabled={busy}>Create</button>
    </form>
  );
}

function LoginForm({
  busy,
  onLogin
}: {
  busy: boolean;
  onLogin: (payload: { username: string; password: string }) => void;
}) {
  const [username, setUsername] = useState("superadmin");
  const [password, setPassword] = useState("");

  return (
    <form className="card form-grid auth-card" onSubmit={(event) => submit(event, () => onLogin({ username, password }))}>
      <h2>Sign In</h2>
      <label>
        Username
        <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
      </label>
      <label>
        Password
        <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
      </label>
      <button type="submit" disabled={busy}>Sign in</button>
    </form>
  );
}

function PasswordChangeForm({
  busy,
  forced,
  onChangePassword
}: {
  busy: boolean;
  forced?: boolean;
  onChangePassword: (payload: { current_password: string; new_password: string }) => void;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  return (
    <form className="card form-grid auth-card" onSubmit={(event) => submit(event, () => onChangePassword({ current_password: currentPassword, new_password: newPassword }))}>
      <h2>{forced ? "Change Temporary Password" : "Change Password"}</h2>
      <label>
        Current password
        <input value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} type="password" autoComplete="current-password" />
      </label>
      <label>
        New password
        <input value={newPassword} onChange={(event) => setNewPassword(event.target.value)} type="password" minLength={10} autoComplete="new-password" />
      </label>
      <button type="submit" disabled={busy}>Save</button>
    </form>
  );
}

function AdminPanel({
  busy,
  currentUser,
  users,
  authSettings,
  availableRoles,
  onSaveAuthSettings,
  onCreateUser,
  onResetPassword,
  onSetBlocked,
  onDeleteUser
}: {
  busy: boolean;
  currentUser: User;
  users: User[];
  authSettings: AuthSettingsResponse | null;
  availableRoles: Role[];
  onSaveAuthSettings: (authTTLHours: number) => void;
  onCreateUser: (payload: { username: string; role: Role; description: string }) => void;
  onResetPassword: (user: User) => void;
  onSetBlocked: (user: User, blocked: boolean) => void;
  onDeleteUser: (user: User) => void;
}) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>(availableRoles[0] ?? "client");
  const [description, setDescription] = useState("");
  const [authTTLHours, setAuthTTLHours] = useState("12");

  useEffect(() => {
    setRole(availableRoles[0] ?? "client");
  }, [availableRoles.join("|")]);

  useEffect(() => {
    if (authSettings?.policy.auth_ttl_hours) {
      setAuthTTLHours(String(authSettings.policy.auth_ttl_hours));
    }
  }, [authSettings?.policy.auth_ttl_hours]);

  const canEditAuth = currentUser.role === "super_admin";
  const authTTLChoices = authSettings?.policy.allowed_auth_ttl_hours?.length ? authSettings.policy.allowed_auth_ttl_hours : [1, 4, 8, 12, 24, 72, 168];

  return (
    <div className="admin-stack">
      <form className="card form-grid compact-form" onSubmit={(event) => submit(event, () => onSaveAuthSettings(Number(authTTLHours)))}>
        <h2>
          Login Sessions
          <HelpTip text="Global TTL for ordinary login sessions across all roles. It applies to new logins; existing sessions keep their lifetime until the next login or logout." />
        </h2>
        <div className="operator-strip pow-summary">
          <div className="has-tooltip" data-tooltip="After this time, the server stops accepting the login cookie and the UI asks the user to sign in again.">
            <span>Login TTL</span>
            <strong>{authTTLHours} h</strong>
          </div>
          <div className="has-tooltip" data-tooltip="A repeated client login revokes the previous client login session.">
            <span>Clients</span>
            <strong>latest login wins</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Administrators and super administrators may have multiple active login sessions, each limited by the global TTL.">
            <span>Admins</span>
            <strong>parallel</strong>
          </div>
        </div>
        <label>
          <span className="label-title">
            Login TTL
            <HelpTip text="This value applies globally to new login sessions for clients, administrators, and super administrators." />
          </span>
          <select
            value={authTTLHours}
            disabled={!canEditAuth}
            title={canEditAuth ? "Lifetime for new login sessions." : "Only a super administrator can change login TTL."}
            onChange={(event) => setAuthTTLHours(event.target.value)}
          >
            {authTTLChoices.map((value) => <option key={value} value={value}>{value} h</option>)}
          </select>
        </label>
        <button type="submit" disabled={busy || !canEditAuth}>Save Login TTL</button>
      </form>

      <form className="card form-grid compact-form" onSubmit={(event) => submit(event, () => {
        onCreateUser({ username, role, description });
        setUsername("");
        setDescription("");
      })}>
        <h2>Users</h2>
        <div className="inline-grid">
          <label>
            Username
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label>
            Role
            <select value={role} onChange={(event) => setRole(event.target.value as Role)}>
              {availableRoles.map((item) => (
                <option value={item} key={item}>{roleLabel(item)}</option>
              ))}
            </select>
          </label>
        </div>
        <label>
          Description
          <input value={description} onChange={(event) => setDescription(event.target.value)} />
        </label>
        <button type="submit" disabled={busy || username.trim() === ""}>Create User</button>
      </form>

      <div className="table-card">
        <div className="table-header">
          <h2>User Accounts</h2>
          <span>{users.length}</span>
        </div>
        <div className="user-table">
          {users.map((user) => {
            const manageable = user.role !== "super_admin" && user.id !== currentUser.id && (currentUser.role === "super_admin" || user.role === "client");
            return (
              <article className="user-row" key={user.id}>
                <div>
                  <strong>{user.username}</strong>
                  <span>{roleLabel(user.role)}</span>
                </div>
                <div className="state-tags">
                  {user.must_change_password && <span className="tag tag-warn">password change</span>}
                  {user.is_blocked && <span className="tag tag-danger">blocked</span>}
                  {!user.must_change_password && !user.is_blocked && <span className="tag tag-ok">active</span>}
                </div>
                <div className="row-actions">
                  <button type="button" disabled={busy || !manageable} onClick={() => onResetPassword(user)}>Reset</button>
                  <button type="button" disabled={busy || !manageable} onClick={() => onSetBlocked(user, !user.is_blocked)}>
                    {user.is_blocked ? "Unblock" : "Block"}
                  </button>
                  <button
                    type="button"
                    className="danger-inline"
                    disabled={busy || !manageable}
                    title="Delete the user, close active access, and remove assigned permissions."
                    onClick={() => {
                      const confirmation = window.prompt(`To delete this user, type their username: ${user.username}`);
                      if (confirmation === null) {
                        return;
                      }
                      if (confirmation.trim() === user.username.trim()) {
                        onDeleteUser(user);
                      } else {
                        window.alert("Username did not match. User was not deleted.");
                      }
                    }}
                  >
                    Delete
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function HelpTip({ text }: { text: string }) {
  return (
    <span className="help-tip has-tooltip" data-tooltip={text} tabIndex={0} aria-label={text}>
      ?
    </span>
  );
}

function AccessAdminPanel({
  busy,
  currentUser,
  settings,
  queue,
  computeStatus,
  onSave,
  onRefresh,
  onCloseSession
}: {
  busy: boolean;
  currentUser: User;
  settings: AccessSettingsResponse | null;
  queue: QueueResponse | null;
  computeStatus: ComputeStatusResponse | null;
  onSave: (policy: Pick<AccessPolicy, "required_hashrate_ths" | "hashrate_tolerance_percent" | "proof_window_seconds" | "max_proof_attempts" | "job_timeout_minutes" | "session_ttl_minutes">) => void;
  onRefresh: () => void;
  onCloseSession: (sessionID: string) => void;
}) {
  const policy = settings?.policy ?? queue?.policy;
  const [requiredHashrate, setRequiredHashrate] = useState("1");
  const [hashrateTolerance, setHashrateTolerance] = useState("10");
  const [proofWindow, setProofWindow] = useState("60");
  const [maxProofAttempts, setMaxProofAttempts] = useState("3");
  const [jobTimeout, setJobTimeout] = useState("15");
  const [sessionTTL, setSessionTTL] = useState("30");

  useEffect(() => {
    if (!policy) {
      return;
    }
    setRequiredHashrate(String(policy.required_hashrate_ths ?? 1));
    setHashrateTolerance(String(policy.hashrate_tolerance_percent ?? 10));
    setProofWindow(String(policy.proof_window_seconds ?? 60));
    setMaxProofAttempts(String(policy.max_proof_attempts ?? 3));
    setJobTimeout(String(policy.job_timeout_minutes ?? 15));
    setSessionTTL(String(policy.session_ttl_minutes ?? 30));
  }, [policy?.required_hashrate_ths, policy?.hashrate_tolerance_percent, policy?.proof_window_seconds, policy?.max_proof_attempts, policy?.job_timeout_minutes, policy?.session_ttl_minutes]);

  const canEdit = currentUser.role === "super_admin";
  const targetHashrate = Number(requiredHashrate || "0");
  const tolerance = Number(hashrateTolerance || "0");
  const acceptedHashrate = targetHashrate * (1 - Math.max(0, Math.min(50, tolerance)) / 100);
  const proofWindowSeconds = Number(proofWindow || "0");
  const maxProofAttemptCount = Number(maxProofAttempts || "0");
  const requiredWork = acceptedHashrate * proofWindowSeconds;
  const shareDifficulty = computeStatus?.policy.share_difficulty ?? 0;
  const shareWork = shareDifficulty * 0.004294967296;
  const estimatedShareSeconds = targetHashrate > 0 && shareWork > 0 ? shareWork / targetHashrate : 0;

  return (
    <section className="access-admin-grid">
      <form className="table-card form-grid compact-form" onSubmit={(event) => submit(event, () => onSave({
        required_hashrate_ths: Number(requiredHashrate),
        hashrate_tolerance_percent: Number(hashrateTolerance),
        proof_window_seconds: Number(proofWindow),
        max_proof_attempts: Number(maxProofAttempts),
        job_timeout_minutes: Number(jobTimeout),
        session_ttl_minutes: Number(sessionTTL)
      }))}>
        <div className="table-header">
          <h2>
            PoW Template
            <HelpTip text="Global template for new folders. Existing folders keep their own policy, so lowering the template does not weaken older archives." />
          </h2>
          <button
            type="button"
            className="secondary-inline"
            disabled={busy}
            title="Reload current PoW settings, queue, and active sessions from the server."
            onClick={onRefresh}
          >
            Refresh
          </button>
        </div>
        <div className="operator-strip pow-summary">
          <div className="has-tooltip" data-tooltip="Required simultaneous estimated hashrate. It defines the total work target for the selected window.">
            <span>Hashrate</span>
            <strong>{formatPower(targetHashrate)}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Lower passing threshold after tolerance. The upper tolerance is shown for context; stronger hashrate is not rejected.">
            <span>Pass</span>
            <strong>&gt;= {formatPower(acceptedHashrate)}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Estimated proof work: passing TH/s multiplied by the window. Valid shares must cover this work in one attempt.">
            <span>Work/Attempt</span>
            <strong>{formatWork(requiredWork)}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Approximate interval between valid events at the current Stratum difficulty and configured hashrate. This is an estimate; real shares arrive randomly.">
            <span>Event</span>
            <strong>{estimatedShareSeconds > 0 ? formatDurationSeconds(estimatedShareSeconds) : "-"}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="After a successful proof, the folder opens for a limited time. Access closes after the TTL expires.">
            <span>TTL</span>
            <strong>{sessionTTL || 0} min</strong>
          </div>
        </div>
        <div className="inline-grid">
          <label>
            <span className="label-title">
              TH/s
              <HelpTip text="How much simultaneous compute capacity must be proven. Raising the value directly increases required work." />
            </span>
            <input
              type="number"
              min="0.000001"
              step="0.000001"
              value={requiredHashrate}
              disabled={!canEdit}
              title="Required hashrate in TH/s. Changes the required_work_th calculation."
              onChange={(event) => setRequiredHashrate(event.target.value)}
            />
          </label>
          <label>
            <span className="label-title">
              Tolerance, %
              <HelpTip text="Lower tolerance for target hashrate instability. At 14 TH/s and 10%, proof passes from 12.6 TH/s. Stronger hashrate is not rejected." />
            </span>
            <input
              type="number"
              min="0"
              max="50"
              step="1"
              value={hashrateTolerance}
              disabled={!canEdit}
              title="Tolerance for required hashrate. Used as the lower passing threshold."
              onChange={(event) => setHashrateTolerance(event.target.value)}
            />
          </label>
        </div>
        <div className="inline-grid">
          <label>
            <span className="label-title">
              Window
              <HelpTip text="Duration of one proof attempt. When a folder is created, the value is copied into its policy and later into the PoW job snapshot." />
            </span>
            <select
              value={proofWindow}
              disabled={!canEdit}
              title="Window for one PoW attempt on new folders."
              onChange={(event) => setProofWindow(event.target.value)}
            >
              {[5, 10, 15, 30, 60, 120, 300, 600].map((value) => <option key={value} value={value}>{value} sec</option>)}
            </select>
          </label>
          <label>
            <span className="label-title">
              Attempts
              <HelpTip text="How many independent windows are allowed for one access request. Increasing attempts on an existing folder is considered weakening and is rejected." />
            </span>
            <select
              value={maxProofAttempts}
              disabled={!canEdit}
              title="Number of attempts for new folders."
              onChange={(event) => setMaxProofAttempts(event.target.value)}
            >
              {[1, 2, 3, 4, 5, 10].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
        </div>
        <label>
          <span className="label-title">
            Access TTL
            <HelpTip text="Lifetime of the open session after a successful proof. While the session is active, the client can read and download permitted files." />
          </span>
          <select
            value={sessionTTL}
            disabled={!canEdit}
            title="Lifetime of the opened folder."
            onChange={(event) => setSessionTTL(event.target.value)}
          >
            {[10, 15, 30, 60].map((value) => <option key={value} value={value}>{value} min</option>)}
          </select>
        </label>
        <div className="state-tags">
          <span className="tag tag-ok has-tooltip" data-tooltip="Target hashrate. This is the capacity the system attempts to verify over time.">{formatPower(targetHashrate)}</span>
          <span className="tag tag-warn has-tooltip" data-tooltip="Lower passing threshold after tolerance.">{formatPower(acceptedHashrate)}</span>
          <span className="tag has-tooltip" data-tooltip="Duration and attempt count that will be written to the new folder.">{proofWindowSeconds || 0} sec x {maxProofAttemptCount || 0}</span>
          <span className="tag has-tooltip" data-tooltip="Worker names are not configured as a requirement, but they are shown in telemetry and queue views.">workers are telemetry only</span>
          <span className="tag tag-danger has-tooltip" data-tooltip="Only one active access operation is allowed at a time: either a running job or an open TTL session.">one active session</span>
        </div>
        <button
          type="submit"
          disabled={busy || !canEdit}
          title={canEdit ? "Save the PoW template. It applies to new folders but does not weaken existing ones." : "Only a super administrator can change the PoW template."}
        >
          Save Template
        </button>
      </form>

      <div className="table-card">
        <div className="table-header">
          <h2>
            Access Queue
            <HelpTip text="Shows who is currently proving work, who is waiting in the queue, and who already has an open TTL access session." />
          </h2>
          <span className="has-tooltip" data-tooltip="Number of queued/running PoW jobs. Completed jobs may appear lower in the recent event list.">
            {queue?.jobs.filter((job) => job.status === "queued" || job.status === "running").length ?? 0}
          </span>
        </div>
        {(!queue || queue.jobs.length === 0) && <div className="placeholder">No PoW jobs</div>}
        {queue && queue.jobs.length > 0 && (
          <div className="pow-list">
            {queue.jobs.slice(0, 8).map((job) => (
              <article className="pow-row" key={job.id}>
                <div>
                  <strong>{job.username ?? job.user_id}</strong>
                  <span className="has-tooltip" data-tooltip="Valid work for the job versus required work. For a running job, this is live progress.">
                    {jobStatusLabel(job.status)} / {formatWork(job.valid_work_th)} of {formatWork(job.required_work_th)}
                  </span>
                  <div className="progress-track" aria-label={`Progress ${progressPercent(job)}%`} title={`PoW progress: ${progressPercent(job)}%`}>
                    <div className="progress-fill" style={{ width: `${progressPercent(job)}%` }} />
                  </div>
                </div>
                <div className="state-tags">
                  {job.status === "queued" && <span className="tag tag-warn has-tooltip" data-tooltip="Queue position. Only one PoW job or one active session can run at a time.">#{job.queue_position}</span>}
                  {job.status === "running" && <span className="tag tag-ok has-tooltip" data-tooltip="The job is active; the proxy is assigning work to connected worker names.">running</span>}
                  <span className="tag has-tooltip" data-tooltip="Completion percentage by valid work.">{progressPercent(job)}%</span>
                  <span className="tag has-tooltip" data-tooltip="Required hashrate used when this job was created.">{formatPower(job.required_hashrate_ths)}</span>
                  <span className="tag has-tooltip" data-tooltip="How many distinct worker names submitted valid shares. This is an observation, not a passing requirement.">{job.valid_worker_count} workers</span>
                </div>
              </article>
            ))}
          </div>
        )}
        {queue && queue.active_sessions.length > 0 && (
          <div className="active-session-strip">
            {queue.active_sessions.map((session) => (
              <article className="session-chip" key={session.id}>
                <span className="tag tag-danger">active</span>
                <strong>{session.username ?? session.user_id}</strong>
                <span className="has-tooltip" data-tooltip="The folder remains open for the client until this time. After TTL, the session closes automatically.">until {formatTime(session.expires_at)}</span>
                <button
                  type="button"
                  className="secondary-inline"
                  disabled={busy}
                  title="Force-close the active access session and release the queue."
                  onClick={() => onCloseSession(session.id)}
                >
                  Close
                </button>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function ComputeAdminPanel({
  busy,
  currentUser,
  status,
  onSave,
  onRefresh,
  onResetWorker
}: {
  busy: boolean;
  currentUser: User;
  status: ComputeStatusResponse | null;
  onSave: (payload: { enabled: boolean; share_difficulty: number; stratum_password?: string }) => void;
  onRefresh: () => void;
  onResetWorker: (workerID: string) => void;
}) {
  const [enabled, setEnabled] = useState(true);
  const [shareDifficulty, setShareDifficulty] = useState("0.0025");
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (!status?.policy) {
      return;
    }
    setEnabled(status.policy.enabled);
    setShareDifficulty(String(status.policy.share_difficulty));
    setPassword("");
  }, [status?.policy.enabled, status?.policy.share_difficulty, status?.policy.password_updated_at]);

  const canEdit = currentUser.role === "super_admin";
  const shareWork = Number(shareDifficulty || "0") * 0.004294967296;
  const activeJob = status?.active_job;
  const workers = status?.workers ?? [];
  const recentShares = status?.recent_shares ?? [];
  const recentValidShares = recentShares.filter((share) => share.is_valid).length;
  const recentInvalidShares = recentShares.length - recentValidShares;
  const connectedWorkers = workers.filter((worker) => worker.runtime_connections > 0).length;
  const totalShares = recentShares.length;
  const rejectRate = totalShares > 0 ? Math.round((recentInvalidShares / totalShares) * 100) : 0;
  const activeProgress = activeJob ? progressPercent(activeJob) : 0;
  const proofWindowSeconds = activeJob?.proof_window_seconds ?? 0;
  const observedHashrate = activeJob && proofWindowSeconds > 0 ? activeJob.valid_work_th / proofWindowSeconds : 0;

  return (
    <section className="compute-grid">
      <form className="table-card form-grid compact-form" onSubmit={(event) => submit(event, () => {
        const payload: { enabled: boolean; share_difficulty: number; stratum_password?: string } = {
          enabled,
          share_difficulty: Number(shareDifficulty)
        };
        if (password.trim() !== "") {
          payload.stratum_password = password;
        }
        onSave(payload);
      })}>
        <div className="table-header">
          <h2>
            Compute Gateway
            <HelpTip text="Stratum entry point for compute devices. It accepts authorize/submit, verifies shares, and passes results into the PoW access path." />
          </h2>
          <button
            type="button"
            className="secondary-inline"
            disabled={busy}
            title="Reload gateway runtime, active job, worker names, and recent shares."
            onClick={onRefresh}
          >
            Refresh
          </button>
        </div>
        <div className="switch-row">
          <label title="Enables or disables Stratum connections on the embedded compute gateway.">
            <input type="checkbox" checked={enabled} disabled={!canEdit} onChange={(event) => setEnabled(event.target.checked)} />
            <span className="label-title">
              Accept Stratum
              <HelpTip text="When enabled, the gateway accepts compute device connections and can assign work for an active PoW job." />
            </span>
          </label>
          <span className={status?.runtime.running ? "tag tag-ok has-tooltip" : "tag tag-danger has-tooltip"} data-tooltip="TCP listener status for the gateway. If the port is open, devices can connect to Stratum.">
            {status?.runtime.running ? "port open" : "stopped"}
          </span>
        </div>
        <div className="inline-grid">
          <label>
            <span className="label-title">
              Port
              <HelpTip text="TCP port for the Stratum gateway. It is configured by deployment and used by devices as the pool address." />
            </span>
            <input value={status?.policy.stratum_port ?? 3333} disabled readOnly title="Port Stratum gateway." />
          </label>
          <label>
            <span className="label-title">
              Share Difficulty
              <HelpTip text="How much proof work is credited for one valid share. Lower values are convenient for testing; higher values reduce small-share volume." />
            </span>
            <input
              type="number"
              min="0.000001"
              step="0.000001"
              value={shareDifficulty}
              disabled={!canEdit}
              title="Stratum share difficulty."
              onChange={(event) => setShareDifficulty(event.target.value)}
            />
          </label>
        </div>
        <label>
          <span className="label-title">
            Password Stratum
            <HelpTip text="Password provided by the device during mining.authorize. The UI only exposes replacement; the current value is not shown." />
          </span>
          <input
            value={password}
            type="password"
            minLength={8}
            disabled={!canEdit}
            placeholder={status?.policy.password_configured ? "configured, can be replaced" : "not configured"}
            title="Enter a new password only if the current one must be replaced."
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <div className="state-tags">
          <span className="tag has-tooltip" data-tooltip="Address and port where the API listens for Stratum connections inside the container.">{status?.runtime.listen_address ?? "..."}</span>
          <span className={status?.policy.password_configured ? "tag tag-ok has-tooltip" : "tag tag-danger has-tooltip"} data-tooltip="The Stratum password is required by devices during mining.authorize. This only shows whether it is configured.">
            {status?.policy.password_configured ? "password configured" : "password not configured"}
          </span>
          <span className="tag tag-warn has-tooltip" data-tooltip="How much proof work Archivon credits for one valid share at the current difficulty. This is not speed.">{formatWork(shareWork)} per share</span>
        </div>
        <button
          type="submit"
          disabled={busy || !canEdit || Number(shareDifficulty) <= 0}
          title={canEdit ? "Save Stratum gateway settings. A new password is applied only if the field is filled." : "Only a super administrator can change the gateway."}
        >
          Save gateway
        </button>
      </form>

      <div className="table-card">
        <div className="table-header">
          <h2>
            Active Proof
            <HelpTip text="Current running PoW job. Valid work, worker count, and observed TH/s matter more than simple connection presence." />
          </h2>
          <span className="has-tooltip" data-tooltip="Current number of open TCP connections to the Stratum gateway.">
            {status?.runtime.active_connections ?? 0} conn
          </span>
        </div>
        <div className="operator-strip">
          <div className="has-tooltip" data-tooltip="How many worker names currently have an active runtime connection.">
            <span>Workers</span>
            <strong>{connectedWorkers}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="How many recent_shares entries were accepted by the strict verifier. This is a live indicator, not a historical total.">
            <span>Valid</span>
            <strong>{recentValidShares}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="How many recent_shares entries were rejected. Old diagnostic rejects are not included here.">
            <span>Reject</span>
            <strong>{recentInvalidShares}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Rejected-share ratio among recent_shares entries. Useful for quick diagnosis.">
            <span>Reject-rate</span>
            <strong>{rejectRate}%</strong>
          </div>
        </div>
        {!activeJob && <div className="placeholder">No active PoW job</div>}
        {activeJob && (
          <article className="compute-job">
            <div>
              <strong>{activeJob.username}</strong>
              <span className="has-tooltip" data-tooltip="Valid proof work for the current job versus required work.">{formatWork(activeJob.valid_work_th)} of {formatWork(activeJob.required_work_th)}</span>
              <div className="progress-track" aria-label={`Progress ${activeProgress}%`} title={`Current PoW progress: ${activeProgress}%`}>
                <div className="progress-fill" style={{ width: `${activeProgress}%` }} />
              </div>
            </div>
            <div className="state-tags">
              <span className="tag tag-ok has-tooltip" data-tooltip="Completion percentage for the current job by valid work.">{activeProgress}%</span>
              <span className="tag has-tooltip" data-tooltip="Observed hashrate: best-attempt valid work divided by proof window.">{formatPower(observedHashrate)}</span>
              <span className="tag tag-warn has-tooltip" data-tooltip="Window of one proof attempt saved in this job snapshot.">{trimNumber(proofWindowSeconds)} sec</span>
              <span className="tag has-tooltip" data-tooltip="Number of attempts in this PoW job. Any successful attempt opens access.">{activeJob.max_proof_attempts} attempts</span>
              <span className="tag has-tooltip" data-tooltip="Number of distinct workers that submitted valid shares for this job. This is telemetry, not a requirement.">{activeJob.valid_worker_count} workers</span>
              <span className="tag has-tooltip" data-tooltip="Start time of the current PoW job.">{formatDate(activeJob.started_at)}</span>
            </div>
          </article>
        )}
      </div>

      <div className="table-card worker-panel">
        <div className="table-header">
          <h2>
            Worker Names
            <HelpTip text="Worker name distinguishes connected devices. When identical names conflict, the system shows the issue and counts them as one worker name." />
          </h2>
          <span className="has-tooltip" data-tooltip="Number of known worker names in the database. This is not necessarily the current number of physical devices.">
            {status?.workers.length ?? 0}
          </span>
        </div>
        {(!status || status.workers.length === 0) && <div className="placeholder">No connections yet</div>}
        {status && status.workers.length > 0 && (
          <div className="worker-table">
            {status.workers.map((worker) => (
              <article className="worker-row" key={worker.id}>
                <div>
                  <strong>{worker.worker_name}</strong>
                  <span className="has-tooltip" data-tooltip="Last IP:port used by this worker name to connect to the Stratum gateway.">{worker.last_ip || "IP not recorded"}</span>
                  {worker.last_seen_at && <span className="has-tooltip" data-tooltip="Last worker activity time: connection or share submit.">seen {formatTime(worker.last_seen_at)}</span>}
                </div>
                <div className="state-tags">
                  <span className={worker.conflict ? "tag tag-danger has-tooltip" : worker.status === "connected" ? "tag tag-ok has-tooltip" : "tag has-tooltip"} data-tooltip="Current worker status in the database and runtime. Conflict means multiple simultaneous connections with the same worker name.">
                    {worker.conflict ? "conflict" : worker.status}
                  </span>
                  <span className="tag has-tooltip" data-tooltip="How many TCP connections this worker currently has open.">{worker.runtime_connections} conn</span>
                  <span className="tag tag-ok has-tooltip" data-tooltip="Number of valid shares from this worker after the latest statistics reset. If there was no reset, all database history is counted.">{worker.valid_shares} ok total</span>
                  {worker.invalid_shares > 0 && <span className="tag tag-danger has-tooltip" data-tooltip="Number of rejected shares from this worker after the latest statistics reset. If there was no reset, old diagnostics may be included.">{worker.invalid_shares} reject total</span>}
                  {worker.stats_reset_at && <span className="tag has-tooltip" data-tooltip="ok/reject/TH total counters are counted only after this time. Older shares remain in the database.">reset {formatTime(worker.stats_reset_at)}</span>}
                  {worker.last_error && <span className="tag tag-danger has-tooltip" data-tooltip="Last stored worker error.">{worker.last_error}</span>}
                  {canEdit && (
                    <button
                      type="button"
                      className="secondary-inline"
                      disabled={busy}
                      title="Reset displayed ok/reject/TH total counters for this worker. Share history is not deleted."
                      onClick={() => onResetWorker(worker.id)}
                    >
                      Reset
                    </button>
                  )}
                </div>
                <span className="has-tooltip" data-tooltip="Accumulated proof work for this worker after the last statistics reset. This is total TH, not current TH/s.">{formatWork(worker.valid_work_th)} total</span>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="table-card share-panel">
        <div className="table-header">
          <h2>
            Recent Shares
            <HelpTip text="Recent submit events from compute devices. Accepted shares increase active proof work; rejected shares help diagnose settings." />
          </h2>
          <span className="has-tooltip" data-tooltip="Number of recent shares returned by the API for diagnostics.">
            {status?.recent_shares.length ?? 0}
          </span>
        </div>
        {(!status || status.recent_shares.length === 0) && <div className="placeholder">No shares yet</div>}
        {status && status.recent_shares.length > 0 && (
          <div className="share-table">
            {status.recent_shares.map((share) => (
              <article className="share-row" key={share.id}>
                <div>
                  <strong>{share.worker_name || "unknown"}</strong>
                  <span className="has-tooltip" data-tooltip="When the proxy received this share from the worker.">{formatDate(share.submitted_at)}</span>
                </div>
                <code className="has-tooltip" data-tooltip={share.share_hash}>{shortHash(share.share_hash)}</code>
                <div className="state-tags">
                  <span className={share.is_valid ? "tag tag-ok has-tooltip" : "tag tag-danger has-tooltip"} data-tooltip={share.is_valid ? "The share passed verifier checks and was credited to the proof." : "The share was rejected by the verifier. The reason appears in the tag."}>
                    {share.is_valid ? "valid" : share.rejection_reason || "reject"}
                  </span>
                  <span className="tag has-tooltip" data-tooltip="How much proof work was credited for this share. Rejected shares usually count as 0 TH.">{formatWork(share.work_th)}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function AuditAdminPanel({
  busy,
  settings,
  events,
  backups,
  onSavePolicy,
  onExport,
  onCleanup,
  onRestore,
  onRefresh
}: {
  busy: boolean;
  settings: AuditSettingsResponse | null;
  events: AuditEventsResponse | null;
  backups: AuditBackupsResponse | null;
  onSavePolicy: (retentionDays: number) => void;
  onExport: (fileRelated: boolean) => void;
  onCleanup: (olderThanDays: number) => void;
  onRestore: (file: File) => void;
  onRefresh: () => void;
}) {
  const [retentionDays, setRetentionDays] = useState("30");
  const [cleanupDays, setCleanupDays] = useState("30");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);

  useEffect(() => {
    if (!settings?.policy) {
      return;
    }
    setRetentionDays(String(settings.policy.retention_days));
    setCleanupDays(String(settings.policy.retention_days));
  }, [settings?.policy.retention_days]);

  return (
    <section className="audit-grid">
      <form className="table-card form-grid compact-form" onSubmit={(event) => submit(event, () => onSavePolicy(Number(retentionDays)))}>
        <div className="table-header">
          <h2>Audit Log</h2>
          <button type="button" className="secondary-inline" disabled={busy} onClick={onRefresh}>Refresh</button>
        </div>
        <div className="inline-grid">
          <label>
            Retention, days
            <input type="number" min="0" step="1" value={retentionDays} onChange={(event) => setRetentionDays(event.target.value)} />
          </label>
          <label>
            File-related
            <input value={events?.file_activity_count ?? 0} readOnly disabled />
          </label>
        </div>
        <div className="state-tags">
          <span className="tag tag-ok">{settings?.policy.backup_storage ?? "download_only"}</span>
          <span className="tag tag-warn">checksum restore</span>
          <span className="tag tag-danger">system events stay</span>
        </div>
        <button type="submit" disabled={busy || Number(retentionDays) < 0}>Save</button>
      </form>

      <div className="table-card form-grid compact-form">
        <div className="table-header">
          <h2>Export and Cleanup</h2>
          <span>{backups?.backups.length ?? 0}</span>
        </div>
        <div className="row-actions audit-actions">
          <button type="button" className="secondary-inline" disabled={busy} onClick={() => onExport(false)}>Export Audit Log</button>
          <button type="button" className="secondary-inline" disabled={busy} onClick={() => onExport(true)}>Export File Activity</button>
        </div>
        <div className="inline-grid">
          <label>
            Clean older than days
            <input type="number" min="0" step="1" value={cleanupDays} onChange={(event) => setCleanupDays(event.target.value)} />
          </label>
          <button type="button" disabled={busy || Number(cleanupDays) < 0} onClick={() => onCleanup(Number(cleanupDays))}>
            Clean
          </button>
        </div>
        <div className="upload-row">
          <input type="file" accept="application/json,.json" disabled={busy} onChange={(event) => setRestoreFile(event.target.files?.[0] ?? null)} />
          <button type="button" disabled={busy || !restoreFile} onClick={() => restoreFile && onRestore(restoreFile)}>Restore</button>
        </div>
      </div>

      <div className="table-card audit-events-panel">
        <div className="table-header">
          <h2>Events</h2>
          <span>{events?.events.length ?? 0}</span>
        </div>
        {(!events || events.events.length === 0) && <div className="placeholder">Audit log is empty</div>}
        {events && events.events.length > 0 && (
          <div className="audit-event-table">
            {events.events.map((event) => (
              <article className="audit-event-row" key={event.id}>
                <div>
                  <strong>{event.event_type}</strong>
                  <span>{formatDate(event.created_at)} / {event.target_type || "system"}</span>
                </div>
                <div className="state-tags">
                  <span className={event.severity === "critical" ? "tag tag-danger" : event.severity === "warning" ? "tag tag-warn" : "tag"}>
                    {event.severity}
                  </span>
                  {event.ip_address && <span className="tag">{event.ip_address}</span>}
                </div>
                <code>{shortJSON(event.details)}</code>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="table-card audit-backups-panel">
        <div className="table-header">
          <h2>Backup</h2>
          <span>{backups?.backups.length ?? 0}</span>
        </div>
        {(!backups || backups.backups.length === 0) && <div className="placeholder">No backups</div>}
        {backups && backups.backups.length > 0 && (
          <div className="audit-backup-table">
            {backups.backups.map((backup) => (
              <article className="audit-backup-row" key={backup.id}>
                <div>
                  <strong>{backup.file_name}</strong>
                  <span>{formatDate(backup.created_at)} / {backup.event_count} events</span>
                </div>
                <code>{backup.checksum_sha256}</code>
                <div className="state-tags">
                  <span className={backup.restored_at ? "tag tag-ok" : "tag tag-warn"}>
                    {backup.restored_at ? "restored" : "downloaded"}
                  </span>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function ClientPanel({
  busy,
  folders,
  selectedFolder,
  files,
  jobs,
  sessions,
  terminalLines,
  nodeLinkOK,
  onSelectFolder,
  onBlockedByActiveSession,
  onRequestAccess,
  onCancelJob,
  onCloseSession,
  onDownloadFile,
  onRefresh
}: {
  busy: boolean;
  folders: ClientFolder[];
  selectedFolder: ClientFolder | null;
  files: ClientFile[];
  jobs: ClientPowJob[];
  sessions: AccessSession[];
  terminalLines: TerminalLine[];
  nodeLinkOK: boolean;
  onSelectFolder: (folderID: string) => void;
  onBlockedByActiveSession: (session: AccessSession) => void;
  onRequestAccess: (folderID: string) => void;
  onCancelJob: (jobID: string) => void;
  onCloseSession: (sessionID: string) => void;
  onDownloadFile: (file: ClientFile) => void;
  onRefresh: () => void;
}) {
  const [fileQuery, setFileQuery] = useState("");
  const [fileSort, setFileSort] = useState<"name" | "size">("name");
  const [selectedFileID, setSelectedFileID] = useState("");
  const [fileVerifications, setFileVerifications] = useState<Record<string, FileVerification>>({});
  const [blockedSessionFolderID, setBlockedSessionFolderID] = useState("");
  const [expandedClientFileFolders, setExpandedClientFileFolders] = useState<Record<string, boolean>>({});
  const verifyInputRef = useRef<HTMLInputElement | null>(null);
  const verifyTargetRef = useRef<ClientFile | null>(null);
  const verificationTimersRef = useRef<Record<string, number>>({});
  const blockedSessionTimerRef = useRef<number | null>(null);
  const canUnlock = selectedFolder?.access?.can_unlock_and_access === true;
  const folderJobs = selectedFolder
    ? jobs
        .filter((job) => job.folder_id === selectedFolder.id)
        .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())
    : [];
  const activeJob = folderJobs.find((job) => job.status === "queued" || job.status === "running");
  const latestFolderJob = folderJobs[0];
  const activeSession = selectedFolder ? sessions.find((session) => session.folder_id === selectedFolder.id && session.status === "active") : undefined;
  const filesVisible = canUnlock && Boolean(activeSession);
  const statusJob = activeJob ?? latestFolderJob;
  const indicatorState = powIndicatorState(activeSession, statusJob);
  const blockingSession = sessions.find((session) => session.status === "active");
  const nodeRequiredForOpen = !activeSession && !activeJob;
  const accessActionDisabled = busy || (nodeRequiredForOpen && !nodeLinkOK);
  const [folderTTLNow, setFolderTTLNow] = useState(() => Date.now());
  const folderTTLBeepMarkersRef = useRef<Record<string, string>>({});
  const activeSessionByFolder = useMemo(() => {
    return new Map(sessions.filter((session) => session.status === "active").map((session) => [session.folder_id, session]));
  }, [sessions]);
  const visibleFiles = useMemo(() => {
    const normalizedQuery = fileQuery.trim().toLowerCase();
    const filtered = normalizedQuery === "" ? files : files.filter((file) => fileDisplayPath(file).toLowerCase().includes(normalizedQuery));
    return [...filtered].sort((left, right) => {
      if (fileSort === "size") {
        return right.size_bytes - left.size_bytes;
      }
      return fileDisplayPath(left).localeCompare(fileDisplayPath(right), "ru");
    });
  }, [files, fileQuery, fileSort]);
  const visibleFileTree = useMemo(() => buildFileTree(visibleFiles, fileSort), [visibleFiles, fileSort]);

  useEffect(() => {
    setSelectedFileID("");
    setExpandedClientFileFolders({});
    Object.values(verificationTimersRef.current).forEach((timerID) => window.clearTimeout(timerID));
    verificationTimersRef.current = {};
    setFileVerifications({});
  }, [selectedFolder?.id]);

  const toggleClientFileFolder = (folderPath: string) => {
    setExpandedClientFileFolders((current) => ({
      ...current,
      [folderPath]: current[folderPath] === false
    }));
  };

  useEffect(() => {
    if (selectedFileID && !visibleFiles.some((file) => file.id === selectedFileID)) {
      setSelectedFileID("");
    }
  }, [selectedFileID, visibleFiles]);

  useEffect(() => {
    setFileVerifications((current) => {
      const visibleIDs = new Set(files.map((file) => file.id));
      const next: Record<string, FileVerification> = {};
      Object.entries(current).forEach(([fileID, verification]) => {
        if (visibleIDs.has(fileID)) {
          next[fileID] = verification;
        } else if (verificationTimersRef.current[fileID] !== undefined) {
          window.clearTimeout(verificationTimersRef.current[fileID]);
          delete verificationTimersRef.current[fileID];
        }
      });
      return next;
    });
  }, [files]);

  useEffect(() => {
    setFolderTTLNow(Date.now());
    if (sessions.every((session) => session.status !== "active")) {
      return;
    }
    const timer = window.setInterval(() => setFolderTTLNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [sessions]);

  useEffect(() => {
    const activeIDs = new Set(sessions.filter((session) => session.status === "active").map((session) => session.id));
    Object.keys(folderTTLBeepMarkersRef.current).forEach((sessionID) => {
      if (!activeIDs.has(sessionID)) {
        delete folderTTLBeepMarkersRef.current[sessionID];
      }
    });
  }, [sessions]);

  useEffect(() => {
    sessions.filter((session) => session.status === "active").forEach((session) => {
      const remainingSeconds = Math.ceil((new Date(session.expires_at).getTime() - folderTTLNow) / 1000);
      if (remainingSeconds > TTL_TICK_WARNING_SECONDS) {
        return;
      }
      const marker = ttlTickMarker(remainingSeconds);
      if (!marker || folderTTLBeepMarkersRef.current[session.id] === marker) {
        return;
      }
      folderTTLBeepMarkersRef.current[session.id] = marker;
      playTTLWarningTone(marker === "expired" ? "expired" : "tick");
    });
  }, [sessions, folderTTLNow]);

  useEffect(() => {
    if (blockedSessionFolderID && !activeSessionByFolder.has(blockedSessionFolderID)) {
      setBlockedSessionFolderID("");
    }
  }, [blockedSessionFolderID, activeSessionByFolder]);

  useEffect(() => {
    return () => {
      if (blockedSessionTimerRef.current !== null) {
        window.clearTimeout(blockedSessionTimerRef.current);
      }
      Object.values(verificationTimersRef.current).forEach((timerID) => window.clearTimeout(timerID));
      verificationTimersRef.current = {};
    };
  }, []);

  const blinkBlockingSessionFolder = (session: AccessSession) => {
    if (blockedSessionTimerRef.current !== null) {
      window.clearTimeout(blockedSessionTimerRef.current);
    }
    setBlockedSessionFolderID("");
    window.setTimeout(() => setBlockedSessionFolderID(session.folder_id), 0);
    blockedSessionTimerRef.current = window.setTimeout(() => {
      setBlockedSessionFolderID("");
      blockedSessionTimerRef.current = null;
    }, 1800);
  };

  const requestFileVerification = (file: ClientFile) => {
    if (!activeSession) {
      return;
    }
    verifyTargetRef.current = file;
    if (verifyInputRef.current) {
      verifyInputRef.current.value = "";
      verifyInputRef.current.click();
    }
  };

  const clearVerificationTimer = (fileID: string) => {
    if (verificationTimersRef.current[fileID] !== undefined) {
      window.clearTimeout(verificationTimersRef.current[fileID]);
      delete verificationTimersRef.current[fileID];
    }
  };

  const scheduleVerificationClear = (fileID: string) => {
    clearVerificationTimer(fileID);
    verificationTimersRef.current[fileID] = window.setTimeout(() => {
      setFileVerifications((current) => {
        const next = { ...current };
        delete next[fileID];
        return next;
      });
      delete verificationTimersRef.current[fileID];
    }, 10000);
  };

  const handleVerificationFile = async (candidate?: File) => {
    const target = verifyTargetRef.current;
    if (!target || !candidate) {
      return;
    }
    clearVerificationTimer(target.id);
    const startedAt = new Date().toISOString();
    setFileVerifications((current) => ({
      ...current,
      [target.id]: {
        status: "checking",
        checked_name: candidate.name,
        message: "checking...",
        checked_at: startedAt
      }
    }));
    try {
      const digest = await sha256File(candidate);
      const matched = digest.toLowerCase() === target.plaintext_sha256.toLowerCase();
      setFileVerifications((current) => ({
        ...current,
        [target.id]: {
          status: matched ? "matched" : "mismatched",
          checked_name: candidate.name,
          checked_sha256: digest,
          message: matched ? "integrity confirmed" : "file does not match",
          checked_at: new Date().toISOString()
        }
      }));
      scheduleVerificationClear(target.id);
    } catch {
      setFileVerifications((current) => ({
        ...current,
        [target.id]: {
          status: "error",
          checked_name: candidate.name,
          message: "verification unavailable",
          checked_at: new Date().toISOString()
        }
      }));
      scheduleVerificationClear(target.id);
    } finally {
      verifyTargetRef.current = null;
      if (verifyInputRef.current) {
        verifyInputRef.current.value = "";
      }
    }
  };

  return (
    <section className="client-grid">
      <input
        ref={verifyInputRef}
        className="hidden-file-input"
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        onChange={(event) => {
          void handleVerificationFile(event.target.files?.[0]);
        }}
      />
      <div className="table-card storage-list">
        <div className="table-header">
          <h2>Available Folders</h2>
          <button
            type="button"
            className="secondary-inline has-tooltip"
            data-tooltip="Refresh available folders, files, and current access states."
            disabled={busy}
            onClick={onRefresh}
          >
            Refresh
          </button>
        </div>
        <div className="client-panel-body">
          {folders.length === 0 && <div className="placeholder">No granted permissions</div>}
          {folders.map((folder) => {
            const folderSession = activeSessionByFolder.get(folder.id);
            const folderFilesVisible = folder.access?.can_unlock_and_access === true && Boolean(folderSession);
            const displayedFileCount = folder.id === selectedFolder?.id && filesVisible ? visibleFiles.length : folder.file_count;
            const displayedTotalBytes = folder.id === selectedFolder?.id && filesVisible
              ? visibleFiles.reduce((total, file) => total + file.size_bytes, 0)
              : folder.total_bytes;
            const remainingSeconds = folderSession
              ? Math.ceil((new Date(folderSession.expires_at).getTime() - folderTTLNow) / 1000)
              : null;
            const safeRemainingSeconds = Math.max(0, remainingSeconds ?? 0);
            const ttlStateClass = folderTTLStateClass(remainingSeconds);
            const rowClassName = [
              "folder-row",
              selectedFolder?.id === folder.id ? "active" : "",
              folderSession ? `folder-session ${folderSessionRowClass(remainingSeconds)}` : "",
              blockedSessionFolderID === folder.id ? "folder-session-blocked" : ""
            ].filter(Boolean).join(" ");
            const tooltip = folderSession
              ? `Select folder. Access session is active, remaining ${formatTTLCountdown(safeRemainingSeconds)}.`
              : `Select folder. Access right: ${accessLevelLabel(permissionLevel(folder.access))}.`;
            return (
              <button
                className={rowClassName}
                data-tooltip={tooltip}
                type="button"
                key={folder.id}
                aria-pressed={selectedFolder?.id === folder.id}
                onClick={() => onSelectFolder(folder.id)}
              >
                {folderSession && (
                  <span className="folder-session-row">
                    <span
                      className="tag tag-ok folder-open-status has-tooltip"
                      data-tooltip="A TTL session is currently open for this folder."
                    >
                      Open
                    </span>
                    <span
                      className={`tag folder-ttl-countdown ttl-countdown ${ttlStateClass} has-tooltip`}
                      data-tooltip={`Remaining ${formatTTLCountdown(safeRemainingSeconds)}. Access closes at ${formatTime(folderSession.expires_at)}.`}
                      aria-live="polite"
                    >
                      {formatTTLCountdown(safeRemainingSeconds)}
                    </span>
                  </span>
                )}
                <span className="folder-row-main">
                  <strong>{folder.name}</strong>
                  {folder.description && <small className="folder-description">{folder.description}</small>}
                </span>
                <span className="folder-metrics">
                  <span
                    className="tag folder-file-count has-tooltip"
                    data-tooltip={folderFilesVisible ? `Files in folder. Total size: ${formatBytes(displayedTotalBytes)}.` : "Files are hidden until the folder is opened."}
                  >
                    {folderFilesVisible ? formatFileCount(displayedFileCount) : "files hidden"}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="table-card file-panel">
        <div className="table-header">
          <h2>{selectedFolder?.name ?? "Files"}</h2>
          <span className="has-tooltip" data-tooltip="Number of files visible only after opening the folder.">{filesVisible ? visibleFiles.length : 0}</span>
        </div>
        <div className="client-panel-body">
          {!selectedFolder && <div className="placeholder">Select a folder</div>}
          {selectedFolder && !canUnlock && <div className="placeholder">Access right is not granted</div>}
          {selectedFolder && canUnlock && !activeSession && <div className="placeholder">Files are hidden until the folder is opened</div>}
          {selectedFolder && filesVisible && files.length === 0 && <div className="placeholder">No available files</div>}
          {selectedFolder && filesVisible && (
            <>
              <div className="file-filter-row">
                <label>
                  Search
                  <input value={fileQuery} onChange={(event) => setFileQuery(event.target.value)} />
                </label>
                <label>
                  Sort
                  <select value={fileSort} onChange={(event) => setFileSort(event.target.value as "name" | "size")}>
                    <option value="name">by name</option>
                    <option value="size">largest first</option>
                  </select>
                </label>
              </div>
              {files.length > 0 && visibleFiles.length === 0 && <div className="placeholder">No matches</div>}
              <FileTree
                tree={visibleFileTree}
                expandedFolders={expandedClientFileFolders}
                onToggleFolder={toggleClientFileFolder}
                renderFile={(file) => {
                  const isSelectedFile = selectedFileID === file.id;
                  const verification = fileVerifications[file.id];
                  const fileRowClassName = ["client-file-row", isSelectedFile ? "active" : ""].filter(Boolean).join(" ");
                  return (
                    <article
                      className={fileRowClassName}
                      data-selected={isSelectedFile ? "true" : undefined}
                      tabIndex={0}
                      onClick={() => setSelectedFileID(file.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedFileID(file.id);
                        }
                      }}
                    >
                      <div className="client-file-info">
                        <strong>{file.name}</strong>
                        <span>{formatBytes(file.size_bytes)}</span>
                        <code className="client-file-checksum">{file.plaintext_sha256}</code>
                      </div>
                      <div className="client-file-actions">
                        <button
                          type="button"
                          className={[
                            "secondary-inline",
                            "file-verify-button",
                            "has-tooltip",
                            verification ? `file-verify-button-${verification.status}` : ""
                          ].filter(Boolean).join(" ")}
                          data-tooltip={
                            verification
                              ? fileVerificationTooltip(verification)
                              : activeSession
                                ? "Choose a local file and compare its SHA-256 with the Archivon checksum. The file is not sent to the server."
                                : "Verification becomes available after the folder is opened."
                          }
                          disabled={busy || !activeSession || verification?.status === "checking"}
                          onClick={(event) => {
                            event.stopPropagation();
                            requestFileVerification(file);
                          }}
                        >
                          {fileVerificationButtonLabel(verification)}
                        </button>
                        <button
                          type="button"
                          className="secondary-inline has-tooltip"
                          data-tooltip={activeSession ? "Download the file through the active TTL access session." : "Download becomes available after the folder is opened."}
                          disabled={busy || !activeSession}
                          onClick={(event) => {
                            event.stopPropagation();
                            onDownloadFile(file);
                          }}
                        >
                          Download
                        </button>
                      </div>
                    </article>
                  );
                }}
              />
            </>
          )}
        </div>
      </div>

      <div className="table-card access-panel">
        <div className="table-header">
          <h2>Access</h2>
          <div className={`access-header-actions ${indicatorState !== "idle" ? "has-progress" : ""}`}>
            <span
              className={`${accessStatusClass(activeSession, statusJob)} has-tooltip`}
              data-tooltip={accessStatusTooltip(activeSession, statusJob)}
            >
              {accessStatusLabel(activeSession, statusJob)}
            </span>
            <span
              className={`pow-activity-bar pow-activity-${indicatorState} has-tooltip ${indicatorState !== "idle" ? "is-open" : ""}`}
              data-tooltip={powIndicatorTooltip(activeSession, statusJob)}
              aria-label={accessStatusLabel(activeSession, statusJob)}
              aria-hidden={indicatorState === "idle"}
            >
              <span className="pow-activity-segment" />
            </span>
            {selectedFolder && canUnlock && (
              <button
                type="button"
                className="has-tooltip"
                data-tooltip={!activeSession && !activeJob && blockingSession ? "Close the open TTL access session first. While it is active, no new PoW job is queued." : accessActionTooltip(activeSession, activeJob, nodeLinkOK)}
                disabled={accessActionDisabled}
                onClick={() => {
                  if (activeSession) {
                    onCloseSession(activeSession.id);
                    return;
                  }
                  if (activeJob) {
                    onCancelJob(activeJob.id);
                    return;
                  }
                  if (blockingSession) {
                    blinkBlockingSessionFolder(blockingSession);
                    onBlockedByActiveSession(blockingSession);
                    return;
                  }
                  if (!nodeLinkOK) {
                    return;
                  }
                  onRequestAccess(selectedFolder.id);
                }}
              >
                {activeSession ? "Close" : activeJob ? "Cancel" : "Open"}
              </button>
            )}
          </div>
        </div>
        <div className="client-panel-body">
          {!selectedFolder && <div className="placeholder">Select a folder</div>}
          {selectedFolder && !canUnlock && <div className="placeholder">Access right is not granted</div>}
          {selectedFolder && canUnlock && (
            <div className="pow-list pow-list-terminal-only">
              <AccessTerminal lines={terminalLines} nodeLinkOK={nodeLinkOK} />
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function AccessTerminal({ lines, nodeLinkOK }: { lines: TerminalLine[]; nodeLinkOK: boolean }) {
  const terminalWindowRef = useRef<HTMLDivElement | null>(null);
  const visibleLines: TerminalLine[] = lines.length > 0
    ? lines
    : [{
        at: new Date().toISOString(),
        source: "terminal",
        level: "muted",
        message: "closed"
      }];

  useEffect(() => {
    const terminalWindow = terminalWindowRef.current;
    if (!terminalWindow) {
      return;
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }, [visibleLines]);

  return (
    <section className="terminal-shell" aria-label="Access Terminal">
      <div className="terminal-header">
        <span>Compute node / gateway</span>
        <span
          className="node-link-status has-tooltip"
          data-tooltip={nodeLinkOK ? "At least one live compute node connection to the gateway is present." : "There are no live compute node connections to the gateway right now."}
        >
          <span>Node link:</span>
          <small className={nodeLinkOK ? "node-link-ok" : "node-link-fail"}>{nodeLinkOK ? "OK" : "X"}</small>
        </span>
      </div>
      <div className="terminal-window" role="log" aria-live="polite" ref={terminalWindowRef}>
        {visibleLines.map((line, index) => (
          <div className={`terminal-line terminal-${line.level}`} key={`${line.at}-${index}-${line.message}`}>
            <span>{formatTerminalTime(line.at)}</span>
            <b>{terminalSourceLabel(line.source)}</b>
            <code>{line.message}</code>
          </div>
        ))}
      </div>
    </section>
  );
}

function StoragePanel({
  busy,
  storageAvailable,
  folders,
  selectedFolder,
  defaultPoWPolicy,
  files,
  clientUsers,
  permissions,
  uploadProgress,
  adminDAVSession,
  onSelectFolder,
  onClearUploadProgress,
  onCreateFolder,
  onDeleteFolder,
  onUploadFiles,
  onExportFolderBackup,
  onImportFolderBackup,
  onCreateAdminDAVSession,
  onDeleteFile,
  onSetPermission,
  onRefresh
}: {
  busy: boolean;
  storageAvailable: boolean;
  folders: ProtectedFolder[];
  selectedFolder: ProtectedFolder | null;
  defaultPoWPolicy: AccessPolicy | null;
  files: ProtectedFile[];
  clientUsers: User[];
  permissions: FolderPermission[];
  uploadProgress: UploadProgress | null;
  adminDAVSession: AdminDAVCredentials | null;
  onSelectFolder: (folderID: string) => void;
  onClearUploadProgress: () => void;
  onCreateFolder: (payload: { name: string; description: string; pow_policy: FolderPoWPolicy }) => void;
  onDeleteFolder: (folderID: string) => void;
  onUploadFiles: (folderID: string, files: File[]) => void;
  onExportFolderBackup: (folderID: string, folderName: string) => void;
  onImportFolderBackup: (file: File) => void;
  onCreateAdminDAVSession: (folderID: string) => void;
  onDeleteFile: (fileID: string) => void;
  onSetPermission: (folderID: string, userID: string, access: AccessRights) => void;
  onRefresh: () => void;
}) {
  const [folderName, setFolderName] = useState("");
  const [folderDescription, setFolderDescription] = useState("");
  const [folderHashrate, setFolderHashrate] = useState("1");
  const [folderTolerance, setFolderTolerance] = useState("10");
  const [folderWindow, setFolderWindow] = useState("60");
  const [folderAttempts, setFolderAttempts] = useState("3");
  const [uploadFiles, setUploadFiles] = useState<File[]>([]);
  const [uploadInputKey, setUploadInputKey] = useState(0);
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [backupInputKey, setBackupInputKey] = useState(0);
  const [expandedStorageFileFolders, setExpandedStorageFileFolders] = useState<Record<string, boolean>>({});
  const [copiedAdminDavField, setCopiedAdminDavField] = useState<string | null>(null);
  const [copyFailedAdminDavField, setCopyFailedAdminDavField] = useState<string | null>(null);
  const folderUploadInputRef = useRef<HTMLInputElement | null>(null);
  const permissionByUserID = useMemo(() => new Map(permissions.map((permission) => [permission.user_id, permission])), [permissions]);
  const permissionRank: Record<AccessLevel, number> = { unlock: 0, none: 1 };
  const sortedClientUsers = useMemo(() => {
    return [...clientUsers].sort((left, right) => {
      const leftRank = permissionRank[permissionLevel(permissionByUserID.get(left.id))];
      const rightRank = permissionRank[permissionLevel(permissionByUserID.get(right.id))];
      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }
      return left.username.localeCompare(right.username, "en");
    });
  }, [clientUsers, permissions]);
  const defaultPolicy = useMemo<FolderPoWPolicy>(() => ({
    required_hashrate_ths: defaultPoWPolicy?.required_hashrate_ths ?? 1,
    hashrate_tolerance_percent: defaultPoWPolicy?.hashrate_tolerance_percent ?? 10,
    proof_window_seconds: defaultPoWPolicy?.proof_window_seconds ?? 60,
    max_proof_attempts: defaultPoWPolicy?.max_proof_attempts ?? 3
  }), [defaultPoWPolicy]);
  const folderAcceptedHashrate = Number(folderHashrate || "0") * (1 - Math.max(0, Math.min(50, Number(folderTolerance || "0"))) / 100);
  const folderRequiredWork = folderAcceptedHashrate * Number(folderWindow || "0");
  const selectedUploadBytes = uploadFiles.reduce((total, file) => total + file.size, 0);
  const uploadCurrentFraction = uploadProgress?.status === "running" && uploadProgress.current_total && uploadProgress.current_total > 0
    ? Math.max(0, Math.min(1, (uploadProgress.current_loaded ?? 0) / uploadProgress.current_total))
    : 0;
  const uploadProgressPercent = uploadProgress && uploadProgress.total > 0
    ? Math.round(((uploadProgress.completed + uploadCurrentFraction) / uploadProgress.total) * 100)
    : 0;
  const uploadCurrentPercent = uploadProgress?.current_total && uploadProgress.current_total > 0
    ? Math.round(((uploadProgress.current_loaded ?? 0) / uploadProgress.current_total) * 100)
    : 0;
  const uploadProgressTitle = uploadProgress
    ? uploadProgress.status === "done"
      ? `Done: ${formatFileCount(uploadProgress.completed)}`
      : uploadProgress.status === "error"
        ? `Error on file ${uploadProgress.current_file || "..."}`
        : `Loading ${uploadProgress.completed} of ${uploadProgress.total}`
    : `Selected: ${formatFileCount(uploadFiles.length)}`;
  const uploadProgressDetails = uploadProgress
    ? uploadProgress.status === "done"
      ? "All selected files were added to the protected folder"
      : uploadProgress.status === "error"
        ? `${uploadProgress.current_file || "file"}: ${uploadProgress.error_message || "upload error"}`
      : uploadProgress.current_file || "preparing"
    : `${formatFileCount(uploadFiles.length)} / ${formatBytes(selectedUploadBytes)}`;
  const uploadProgressMeta = uploadProgress?.status === "running" && uploadProgress.current_total && uploadProgress.current_total > 0
    ? `${formatBytes(uploadProgress.current_loaded ?? 0)} / ${formatBytes(uploadProgress.current_total)} · ${uploadCurrentPercent}%`
    : uploadProgress?.status === "error"
      ? `${uploadProgress.completed} of ${uploadProgress.total}`
      : `${uploadProgressPercent}%`;
  const uploadProgressClass = uploadProgress ? `upload-progress upload-progress-${uploadProgress.status}` : "upload-progress upload-progress-selected";
  const storageFileTree = useMemo(() => buildFileTree(files, "name"), [files]);

  useEffect(() => {
    setFolderHashrate(String(defaultPolicy.required_hashrate_ths));
    setFolderTolerance(String(defaultPolicy.hashrate_tolerance_percent));
    setFolderWindow(String(defaultPolicy.proof_window_seconds));
    setFolderAttempts(String(defaultPolicy.max_proof_attempts));
  }, [defaultPolicy.required_hashrate_ths, defaultPolicy.hashrate_tolerance_percent, defaultPolicy.proof_window_seconds, defaultPolicy.max_proof_attempts]);

  useEffect(() => {
    const input = folderUploadInputRef.current;
    if (!input) {
      return;
    }
    input.setAttribute("webkitdirectory", "");
    input.setAttribute("directory", "");
  }, [uploadInputKey]);

  useEffect(() => {
    setExpandedStorageFileFolders({});
  }, [selectedFolder?.id]);

  useEffect(() => {
    setCopiedAdminDavField(null);
    setCopyFailedAdminDavField(null);
  }, [selectedFolder?.id, adminDAVSession?.dav_username]);

  const toggleStorageFileFolder = (folderPath: string) => {
    setExpandedStorageFileFolders((current) => ({
      ...current,
      [folderPath]: current[folderPath] === false
    }));
  };

  const copyAdminDAVValue = async (field: string, value: string) => {
    try {
      await copyTextToClipboard(value);
      setCopiedAdminDavField(field);
      setCopyFailedAdminDavField(null);
      window.setTimeout(() => {
        setCopiedAdminDavField((current) => current === field ? null : current);
      }, 1600);
    } catch {
      setCopyFailedAdminDavField(field);
      setCopiedAdminDavField(null);
      window.setTimeout(() => {
        setCopyFailedAdminDavField((current) => current === field ? null : current);
      }, 2200);
    }
  };

  const adminDAVRows = adminDAVSession ? [
    {
      id: "url",
      label: "Address",
      value: adminDAVSession.dav_url,
      tooltip: "Copy the administrative WebDAV address for the selected folder."
    },
    {
      id: "username",
      label: "Username",
      value: adminDAVSession.dav_username,
      tooltip: "Copy the temporary WebDAV username for administrative uploads."
    },
    {
      id: "password",
      label: "Password",
      value: adminDAVSession.dav_password,
      tooltip: "Copy the temporary WebDAV password. It is shown only after access is created."
    }
  ] : [];

  return (
    <section className="storage-grid">
      <div className="table-card storage-list">
        <div className="table-header">
          <h2>Protected Folders</h2>
          <button type="button" className="secondary-inline" disabled={busy} onClick={onRefresh}>Refresh</button>
        </div>
        <div className="section-count">
          <span>{folders.length}</span>
        </div>
        {folders.length === 0 && <div className="placeholder">No folders</div>}
        {folders.map((folder) => (
          <button
            className={selectedFolder?.id === folder.id ? "folder-row active" : "folder-row"}
            type="button"
            key={folder.id}
            onClick={() => onSelectFolder(folder.id)}
          >
            <span>
              <strong>{folder.name}</strong>
              {folder.description && <small>{folder.description}</small>}
              <small className={folder.unlock_usernames.length > 0 ? "folder-unlock-users" : "folder-unlock-users is-empty"}>
                Access: {folder.unlock_usernames.length > 0 ? folder.unlock_usernames.join(", ") : "no users"}
              </small>
              <small>Created: {formatAuditDate(folder.created_at)}</small>
              <small>Updated: {formatAuditDate(folder.updated_at)}</small>
              <small>PoW {formatPower(folder.pow_policy.required_hashrate_ths)} / {folder.pow_policy.proof_window_seconds} sec</small>
            </span>
            <span className="folder-metrics">
              <b>{folder.file_count}</b>
              <small>{formatBytes(folder.total_bytes)}</small>
            </span>
          </button>
        ))}
      </div>

      <div className="table-card permissions-panel">
        <div className="table-header">
          <h2>Folder Permissions</h2>
          <span>{clientUsers.length}</span>
        </div>
        {!selectedFolder && <div className="placeholder">Select a folder</div>}
        {selectedFolder && clientUsers.length === 0 && <div className="placeholder">No client users</div>}
        {selectedFolder && clientUsers.length > 0 && (
          <div className="permission-table">
            {sortedClientUsers.map((user) => {
              const permission = permissionByUserID.get(user.id);
              const level = permissionLevel(permission);
              return (
                <article className="permission-row" key={user.id}>
                  <strong>{user.username}</strong>
                  <div className="row-actions access-actions">
                    {(["none", "unlock"] as AccessLevel[]).map((choice) => (
                      <button
                        type="button"
                        key={choice}
                        className={level === choice ? "secondary-inline active-choice" : "secondary-inline"}
                        disabled={busy}
                        onClick={() => onSetPermission(selectedFolder.id, user.id, accessPreset(choice))}
                      >
                        {accessLevelLabel(choice)}
                      </button>
                    ))}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>

      <div className="table-card file-panel">
        <div className="table-header">
          <h2>{selectedFolder?.name ?? "Files"}</h2>
          <div className="row-actions">
            <span>{files.length}</span>
            {selectedFolder && (
              <button
                type="button"
                className="danger-inline"
                disabled={busy}
                title="Delete the folder, its files, permissions, and active sessions without opening contents."
                onClick={() => {
                  const confirmation = window.prompt(`To delete this folder, type its name: ${selectedFolder.name}`);
                  if (confirmation === null) {
                    return;
                  }
                  if (confirmation.trim() === selectedFolder.name.trim()) {
                    onDeleteFolder(selectedFolder.id);
                  } else {
                    window.alert("Folder name did not match. Folder was not deleted.");
                  }
                }}
              >
                Delete Folder
              </button>
            )}
          </div>
        </div>
        <div className="folder-backup-panel">
          <div>
            <strong>Folder Backup</strong>
            <span>{backupFile ? backupFile.name : "Export selected folder or import a backup as a new folder"}</span>
          </div>
          <div className="row-actions">
            <button
              type="button"
              className="secondary-inline"
              disabled={busy || !storageAvailable || !selectedFolder}
              title="Download a backup of the selected folder: folder policy, subfolder tree, files, and checksums."
              onClick={() => selectedFolder && onExportFolderBackup(selectedFolder.id, selectedFolder.name)}
            >
              Export
            </button>
            <input
              key={`backup-${backupInputKey}`}
              type="file"
              accept=".zip,application/zip"
              disabled={busy || !storageAvailable}
              title="Choose an Archivon backup file to restore as a new folder."
              onChange={(event) => setBackupFile(event.target.files?.[0] ?? null)}
            />
            <button
              type="button"
              className="secondary-inline"
              disabled={busy || !storageAvailable || !backupFile}
              title="Import a backup as a new folder. Existing folders are not overwritten."
              onClick={() => {
                if (!backupFile) {
                  return;
                }
                onImportFolderBackup(backupFile);
                setBackupFile(null);
                setBackupInputKey((value) => value + 1);
              }}
            >
              Import Backup
            </button>
          </div>
        </div>
        <form className="upload-row" onSubmit={(event) => submit(event, () => {
          if (selectedFolder && uploadFiles.length > 0) {
            onUploadFiles(selectedFolder.id, uploadFiles);
            setUploadFiles([]);
            setUploadInputKey((value) => value + 1);
          }
        })}>
          <div className="upload-picker-group">
            <input
              key={`files-${uploadInputKey}`}
              type="file"
              multiple
              disabled={busy || !storageAvailable || !selectedFolder}
              title="Select one or more files. Each file will be added sequentially to the selected protected folder."
              onChange={(event) => {
                setUploadFiles(Array.from(event.target.files ?? []));
                onClearUploadProgress();
              }}
            />
            <button
              type="button"
              className="secondary-inline"
              disabled={busy || !storageAvailable || !selectedFolder}
              title="Choose a local folder and upload its files while preserving nested subfolders."
              onClick={() => folderUploadInputRef.current?.click()}
            >
              Choose Folder
            </button>
            <input
              key={`folder-${uploadInputKey}`}
              ref={folderUploadInputRef}
              className="hidden-file-input"
              type="file"
              multiple
              aria-hidden="true"
              tabIndex={-1}
              disabled={busy || !storageAvailable || !selectedFolder}
              onChange={(event) => {
                setUploadFiles(Array.from(event.target.files ?? []));
                onClearUploadProgress();
              }}
            />
          </div>
          <button type="submit" disabled={busy || !storageAvailable || !selectedFolder || uploadFiles.length === 0}>
            {uploadFiles.length > 1 ? `Upload ${uploadFiles.length}` : "Upload"}
          </button>
        </form>
        {(uploadFiles.length > 0 || uploadProgress) && (
          <div className={uploadProgressClass}>
            <div className="upload-progress-line">
              <span className={uploadProgress?.status === "error" ? "tag tag-danger" : uploadProgress?.status === "done" ? "tag tag-ok" : "tag tag-warn"}>
                {uploadProgressTitle}
              </span>
              <strong title={uploadProgressDetails}>{uploadProgressDetails}</strong>
              {uploadProgress && <small>{uploadProgressMeta}</small>}
            </div>
            <div className="progress-track" aria-label={`Upload progress ${uploadProgressPercent}%`} title={`Upload progress ${uploadProgressPercent}%`}>
              <div className="progress-fill" style={{ width: `${uploadProgressPercent}%` }} />
            </div>
          </div>
        )}
        <div className="admin-dav-panel">
          <div className="admin-dav-header">
            <div>
              <strong>WebDAV Upload</strong>
              <span>Temporary access for the selected folder only</span>
            </div>
            <button
              type="button"
              className="secondary-inline has-tooltip"
              data-tooltip="Create a new temporary WebDAV address for administrative file and subfolder uploads. Old access for this folder and administrator is revoked."
              disabled={busy || !storageAvailable || !selectedFolder}
              onClick={() => selectedFolder && onCreateAdminDAVSession(selectedFolder.id)}
            >
              Create Access
            </button>
          </div>
          {!selectedFolder && <div className="placeholder">Select a folder for WebDAV upload</div>}
          {selectedFolder && !adminDAVSession && (
            <div className="placeholder">Access not created</div>
          )}
          {selectedFolder && adminDAVSession && (
            <div className="dav-credentials admin-dav-credentials">
              {adminDAVRows.map((row) => (
                <article className="dav-credential-row" key={row.id}>
                  <span className="has-tooltip" data-tooltip={row.tooltip}>{row.label}</span>
                  <code>{row.value}</code>
                  <button
                    type="button"
                    className="secondary-inline copy-inline has-tooltip"
                    data-tooltip={row.tooltip}
                    onClick={() => copyAdminDAVValue(row.id, row.value)}
                  >
                    {copiedAdminDavField === row.id ? "Copied" : copyFailedAdminDavField === row.id ? "Not copied" : "Copy"}
                  </button>
                </article>
              ))}
              <article className="dav-credential-row">
                <span className="has-tooltip" data-tooltip="Automatic expiration time for temporary administrative WebDAV access.">Valid until</span>
                <code>{formatAuditDate(adminDAVSession.expires_at)}</code>
                <span className="tag tag-warn has-tooltip" data-tooltip="Create new access after expiration.">12 h</span>
              </article>
            </div>
          )}
        </div>
        {files.length === 0 && <div className="placeholder">No files</div>}
        <FileTree
          tree={storageFileTree}
          expandedFolders={expandedStorageFileFolders}
          onToggleFolder={toggleStorageFileFolder}
          renderFile={(file) => (
            <article className="file-row">
              <div>
                <strong>{file.name}</strong>
                <span>{formatBytes(file.size_bytes)} / objects: {file.chunk_count}</span>
                <span>Uploaded: {formatAuditDate(file.created_at)}</span>
                <span>Updated: {formatAuditDate(file.updated_at)}</span>
              </div>
              <code>{file.plaintext_sha256}</code>
              <button
                type="button"
                className="danger-inline"
                disabled={busy}
                title="Delete the file without opening the folder."
                onClick={() => {
                  if (window.confirm(`Delete file "${fileDisplayPath(file)}"?`)) {
                    onDeleteFile(file.id);
                  }
                }}
              >
                Delete
              </button>
            </article>
          )}
        />
      </div>

      <form className="card form-grid compact-form create-folder-card" onSubmit={(event) => submit(event, () => {
        onCreateFolder({
          name: folderName,
          description: folderDescription,
          pow_policy: {
            required_hashrate_ths: Number(folderHashrate),
            hashrate_tolerance_percent: Number(folderTolerance),
            proof_window_seconds: Number(folderWindow),
            max_proof_attempts: Number(folderAttempts)
          }
        });
        setFolderName("");
        setFolderDescription("");
      })}>
        <h2>
          New Folder
          <HelpTip text="The PoW policy is written to the folder when it is created. After that, it can only be strengthened or the folder can be deleted." />
        </h2>
        <label>
          Name
          <input value={folderName} onChange={(event) => setFolderName(event.target.value)} />
        </label>
        <label>
          Description
          <input value={folderDescription} onChange={(event) => setFolderDescription(event.target.value)} />
        </label>
        <div className="operator-strip folder-policy-preview">
          <div className="has-tooltip" data-tooltip="Target simultaneous hashrate for this folder.">
            <span>TH/s</span>
            <strong>{formatPower(Number(folderHashrate || "0"))}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Lower passing threshold after tolerance.">
            <span>Pass</span>
            <strong>&gt;= {formatPower(folderAcceptedHashrate)}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Required work for one attempt.">
            <span>Work</span>
            <strong>{formatWork(folderRequiredWork)}</strong>
          </div>
          <div className="has-tooltip" data-tooltip="Window and attempt count for an access request.">
            <span>Attempts</span>
            <strong>{folderWindow}s x {folderAttempts}</strong>
          </div>
        </div>
        <div className="inline-grid">
          <label>
            <span className="label-title">
              TH/s
              <HelpTip text="Required hashrate for the new folder. This is not a device count, but the total passing hashrate level." />
            </span>
            <input type="number" min="0.000001" step="0.000001" value={folderHashrate} onChange={(event) => setFolderHashrate(event.target.value)} />
          </label>
          <label>
            <span className="label-title">
              Tolerance, %
              <HelpTip text="Tolerance lowers the passing threshold from target hashrate. Use a lower value for stricter folders." />
            </span>
            <input type="number" min="0" max="50" step="1" value={folderTolerance} onChange={(event) => setFolderTolerance(event.target.value)} />
          </label>
        </div>
        <div className="inline-grid">
          <label>
            <span className="label-title">
              Window
              <HelpTip text="How many seconds one proof attempt lasts." />
            </span>
            <select value={folderWindow} onChange={(event) => setFolderWindow(event.target.value)}>
              {[5, 10, 15, 30, 60, 120, 300, 600].map((value) => <option key={value} value={value}>{value} sec</option>)}
            </select>
          </label>
          <label>
            <span className="label-title">
              Attempts
              <HelpTip text="How many windows are allowed per access request. More attempts are more convenient but weaken the barrier." />
            </span>
            <select value={folderAttempts} onChange={(event) => setFolderAttempts(event.target.value)}>
              {[1, 2, 3, 4, 5, 10].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
        </div>
        <button type="submit" disabled={busy || !storageAvailable || folderName.trim() === ""}>Create</button>
      </form>

      <div className="table-card form-grid compact-form folder-policy-card">
        <div className="table-header">
          <h2>
            Folder Policy
            <HelpTip text="The policy is written once when the folder is created and is not changed later. Create a new folder to use a different policy." />
          </h2>
          {selectedFolder && <span>{formatPower(selectedFolder.pow_policy.required_hashrate_ths)}</span>}
        </div>
        {!selectedFolder && <div className="placeholder">Select a folder</div>}
        {selectedFolder && (
          <>
            <div className="state-tags">
              <span className="tag tag-danger has-tooltip" data-tooltip="Policy is immutable after folder creation. Legacy API update requests are also rejected by the server.">sealed</span>
              <span className="tag tag-ok has-tooltip" data-tooltip="Target hashrate written when the folder was created.">{formatPower(selectedFolder.pow_policy.required_hashrate_ths)}</span>
              <span className="tag tag-warn has-tooltip" data-tooltip="Tolerance written when the folder was created.">{selectedFolder.pow_policy.hashrate_tolerance_percent}% tolerance</span>
              <span className="tag has-tooltip" data-tooltip="One proof-attempt window written when the folder was created.">{selectedFolder.pow_policy.proof_window_seconds} sec</span>
              <span className="tag has-tooltip" data-tooltip="Attempt count written when the folder was created.">{selectedFolder.pow_policy.max_proof_attempts} attempts</span>
            </div>
            <div className="operator-strip folder-info-strip">
              <div className="has-tooltip" data-tooltip="Number of active files in the selected folder.">
                <span>Files</span>
                <strong>{formatFileCount(selectedFolder.file_count)}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="Total size of active files in the selected folder.">
                <span>Size</span>
                <strong>{formatBytes(selectedFolder.total_bytes)}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="System creation date of the folder for future audit.">
                <span>Created</span>
                <strong>{formatAuditDate(selectedFolder.created_at)}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="System date of the latest folder record update.">
                <span>Updated</span>
                <strong>{formatAuditDate(selectedFolder.updated_at)}</strong>
              </div>
            </div>
            <div className="operator-strip folder-policy-preview">
              <div className="has-tooltip" data-tooltip="Required simultaneous hashrate to open this folder.">
                <span>TH/s</span>
                <strong>{formatPower(selectedFolder.pow_policy.required_hashrate_ths)}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="Lower passing threshold after tolerance.">
                <span>Pass</span>
                <strong>&gt;= {formatPower(selectedFolder.pow_policy.required_hashrate_ths * (1 - selectedFolder.pow_policy.hashrate_tolerance_percent / 100))}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="Work per attempt: passing hashrate multiplied by the window.">
                <span>Work</span>
                <strong>{formatWork(selectedFolder.pow_policy.required_hashrate_ths * (1 - selectedFolder.pow_policy.hashrate_tolerance_percent / 100) * selectedFolder.pow_policy.proof_window_seconds)}</strong>
              </div>
              <div className="has-tooltip" data-tooltip="Window and attempt count written to the folder.">
                <span>Attempts</span>
                <strong>{selectedFolder.pow_policy.proof_window_seconds}s x {selectedFolder.pow_policy.max_proof_attempts}</strong>
              </div>
            </div>
          </>
        )}
      </div>

    </section>
  );
}

type AccessLevel = "none" | "unlock";

function permissionLevel(access?: Partial<AccessRights>): AccessLevel {
  if (access?.can_unlock_and_access) {
    return "unlock";
  }
  return "none";
}

function accessPreset(level: AccessLevel): AccessRights {
  return {
    can_unlock_and_access: level === "unlock"
  };
}

function accessLevelLabel(level: AccessLevel) {
  if (level === "unlock") {
    return "OK";
  }
  return "none";
}

function StatusPanel({ bootstrap, status }: { bootstrap: BootstrapStatus | null; status: SystemStatus | null }) {
  return (
    <section className="mini-card">
      <h2>System</h2>
      <dl>
        <div>
          <dt>Phase</dt>
          <dd>{status?.phase ?? "..."}</dd>
        </div>
        <div>
          <dt>Environment</dt>
          <dd>{status?.environment ?? "..."}</dd>
        </div>
        <div>
          <dt>Bootstrap</dt>
          <dd>{bootstrap?.required ? "required" : "complete"}</dd>
        </div>
        <div>
          <dt>Migrations</dt>
          <dd>{status?.migrations?.applied_migrations ?? "..."}</dd>
        </div>
        <div>
          <dt>KMS</dt>
          <dd>{status?.kms?.state ?? status?.checks?.kms ?? "..."}</dd>
        </div>
      </dl>
    </section>
  );
}

function KmsPanel({ kms }: { kms: KMSStatus | null }) {
  return (
    <section className="mini-card">
      <h2>KMS</h2>
      <dl>
        <div>
          <dt>State</dt>
          <dd>{kms?.state ?? "..."}</dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{kms?.provider ?? "..."}</dd>
        </div>
        <div>
          <dt>Key</dt>
          <dd>{kms?.key_id ?? "..."}</dd>
        </div>
        <div>
          <dt>Fingerprint</dt>
          <dd>{kms?.fingerprint ?? "..."}</dd>
        </div>
        <div>
          <dt>Format</dt>
          <dd>{kms?.format ?? kms?.reason ?? "..."}</dd>
        </div>
      </dl>
    </section>
  );
}

function SessionPanel({
  user,
  busy,
  showLogout = true,
  onLogout
}: {
  user: User;
  busy: boolean;
  showLogout?: boolean;
  onLogout: () => void;
}) {
  return (
    <section className="mini-card">
      <h2>Session</h2>
      <dl>
        <div>
          <dt>User</dt>
          <dd>{user.username}</dd>
        </div>
        <div>
          <dt>Role</dt>
          <dd>{roleLabel(user.role)}</dd>
        </div>
      </dl>
      {showLogout && (
        <button
          type="button"
          className="secondary-button has-tooltip"
          data-tooltip="Close the current Archivon user session and return to sign-in."
          disabled={busy}
          onClick={onLogout}
        >
          Sign out
        </button>
      )}
    </section>
  );
}

function ClientSessionInfoPanel({
  selectedFolder,
  activeSession
}: {
  selectedFolder: ClientFolder | null;
  activeSession?: AccessSession;
}) {
  const [copiedDavField, setCopiedDavField] = useState<string | null>(null);
  const [copyFailedDavField, setCopyFailedDavField] = useState<string | null>(null);
  const [ttlNow, setTtlNow] = useState(() => Date.now());
  const canUnlock = selectedFolder?.access?.can_unlock_and_access === true;

  useEffect(() => {
    setCopiedDavField(null);
    setCopyFailedDavField(null);
  }, [activeSession?.id, selectedFolder?.id]);

  useEffect(() => {
    setTtlNow(Date.now());
    if (!activeSession) {
      return;
    }
    const timer = window.setInterval(() => setTtlNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [activeSession?.id, activeSession?.expires_at]);

  const ttlRemainingSeconds = activeSession
    ? Math.ceil((new Date(activeSession.expires_at).getTime() - ttlNow) / 1000)
    : null;
  const safeTTLSeconds = Math.max(0, ttlRemainingSeconds ?? 0);
  const ttlStateClass = !activeSession
    ? "ttl-idle"
    : safeTTLSeconds <= 0
      ? "tag-danger ttl-expired"
      : safeTTLSeconds <= 60
        ? "tag-danger ttl-critical"
        : safeTTLSeconds <= 300
          ? "tag-warn ttl-warning"
          : "tag-ok ttl-active";
  const ttlText = activeSession ? formatTTLCountdown(safeTTLSeconds) : "--";
  const ttlTooltip = activeSession
    ? safeTTLSeconds <= 0
      ? "TTL session expired. Access closes at the next state refresh."
      : `Remaining ${formatTTLCountdown(safeTTLSeconds)}. Access closes at ${formatTime(activeSession.expires_at)}.`
    : "There is no active TTL access session.";

  const copyDAVValue = async (field: string, value: string) => {
    try {
      await copyTextToClipboard(value);
      setCopiedDavField(field);
      setCopyFailedDavField(null);
      window.setTimeout(() => {
        setCopiedDavField((current) => current === field ? null : current);
      }, 1600);
    } catch {
      setCopyFailedDavField(field);
      setCopiedDavField(null);
      window.setTimeout(() => {
        setCopyFailedDavField((current) => current === field ? null : current);
      }, 2200);
    }
  };

  const davRows = activeSession?.dav_url ? [
    {
      id: "url",
      label: "Address",
      value: activeSession.dav_url,
      tooltip: "Copy the WebDAV address of the opened folder."
    },
    {
      id: "username",
      label: "Username",
      value: activeSession.dav_username ?? "",
      tooltip: "Copy the temporary WebDAV username for the active TTL session."
    },
    {
      id: "password",
      label: "Password",
      value: activeSession.dav_password ?? "",
      tooltip: "Copy the temporary WebDAV password. It is valid only while the access session is open."
    }
  ] : [];

  return (
    <section className="mini-card client-session-info">
      <h2>Current Access</h2>
      <dl>
        <div>
          <dt>Folder</dt>
          <dd>{selectedFolder?.name ?? "no folder selected"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>
            <span
              className={activeSession ? "tag tag-ok has-tooltip" : canUnlock ? "tag tag-warn has-tooltip" : "tag has-tooltip"}
              data-tooltip={activeSession ? "Folder is open. Files can be read and downloaded until expiration." : canUnlock ? "Folder is closed. Click Open to access it." : "Access right is not granted for the selected folder."}
            >
              {activeSession ? "Open" : "Closed"}
            </span>
          </dd>
        </div>
        <div>
          <dt>Remaining</dt>
          <dd>
            <span
              className={`tag ttl-countdown ${ttlStateClass} has-tooltip`}
              data-tooltip={ttlTooltip}
              aria-live="polite"
            >
              {ttlText}
            </span>
          </dd>
        </div>
      </dl>

      {activeSession?.dav_url && (
        <div className="dav-credentials">
          {davRows.map((row) => (
            <article className="dav-credential-row" key={row.id}>
              <span className="has-tooltip" data-tooltip={row.tooltip}>{row.label}</span>
              <code>{row.value}</code>
              <button
                type="button"
                className="secondary-inline copy-inline has-tooltip"
                data-tooltip={row.tooltip}
                onClick={() => copyDAVValue(row.id, row.value)}
              >
                {copiedDavField === row.id ? "Copied" : copyFailedDavField === row.id ? "Not copied" : "Copy"}
              </button>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function ClientTopbarLogout({ busy, onLogout }: { busy: boolean; onLogout: () => void }) {
  return (
    <button
      type="button"
      className="client-topbar-logout has-tooltip"
      data-tooltip="Close the current Archivon user session and return to sign-in."
      disabled={busy}
      onClick={onLogout}
    >
      Sign out
    </button>
  );
}

function ClientVersionFooter({ status }: { status: SystemStatus | null }) {
  const healthy = status?.status === "ready" || status?.status?.startsWith("phase");
  return (
    <div className="client-version-footer">
      <span
        className={healthy ? "client-version-badge ok has-tooltip" : "client-version-badge has-tooltip"}
        data-tooltip={healthy ? `The system responds and core checks are ready. Internal phase: ${status?.status ?? "unknown"}.` : "The system is still loading or one check is not ready."}
      >
        {healthy ? "[Version: 3.7]" : "[Loading]"}
      </span>
    </div>
  );
}

function SystemBadge({ status }: { status: SystemStatus | null }) {
  const healthy = status?.status === "ready" || status?.status?.startsWith("phase");
  const label = healthy ? "Version: 3.7" : "Loading";
  return (
    <span
      className={healthy ? "system-badge ok has-tooltip" : "system-badge has-tooltip"}
      data-tooltip={healthy ? `The system responds and core checks are ready. Internal phase: ${status?.status ?? "unknown"}.` : "The system is still loading or one check is not ready."}
    >
      {label}
    </span>
  );
}

function roleLabel(role: Role) {
  if (role === "super_admin") {
    return "super admin";
  }
  if (role === "admin") {
    return "admin";
  }
  return "client";
}

function submit(event: FormEvent, action: () => void) {
  event.preventDefault();
  action();
}

function errorMessage(error: unknown) {
  if (error instanceof Error) {
    return ERROR_LABELS[error.message] ?? error.message;
  }
  return "unknown_error";
}

const ERROR_LABELS: Record<string, string> = {
  access_session_required: "Open an access session first",
  active_session_must_be_closed: "Close the session first",
  admin_dav_password_failed: "Failed to create WebDAV password",
  admin_dav_revoke_failed: "Failed to revoke old WebDAV access",
  admin_dav_session_create_failed: "Failed to create WebDAV access",
  auth_ttl_invalid: "Invalid login TTL",
  backup_already_restored: "This backup has already been restored",
  checksum_mismatch: "Backup checksum mismatch",
  file_not_found: "File is unavailable or hidden by permissions",
  file_record_create_failed: "Failed to write the file record to the database",
  file_store_failed: "Failed to store the file",
  folder_pow_policy_immutable: "Folder policy is sealed and cannot be changed after creation",
  folder_entry_create_failed: "Failed to add the file to the folder tree",
  folder_not_found: "Folder not found or unavailable",
  folder_path_create_failed: "Failed to create subfolder in archive",
  forbidden: "Insufficient permissions",
  invalid_credentials: "Invalid username or password",
  invalid_upload_path: "Invalid file or subfolder path",
  network_error: "Network interrupted upload",
  not_authenticated: "Login session is not active",
  password_change_required: "Temporary password must be changed",
  request_aborted: "Upload canceled",
  request_failed: "Server or proxy rejected upload",
  storage_object_create_failed: "Failed to create storage object",
  session_not_found: "Active session not found",
  super_admin_required: "This action is available only to a super administrator",
  transaction_commit_failed: "Failed to commit database write",
  unlock_not_allowed: "Access right is not granted",
  user_session_already_active: "This user is already signed in on another device"
};

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatFileCount(value: number) {
  return `${value} ${value === 1 ? "file" : "files"}`;
}

function fileDisplayPath(file: { name: string; path?: string }) {
  const value = file.path?.trim();
  return value || file.name;
}

function fileDirectoryPath(file: { name: string; path?: string }) {
  const value = fileDisplayPath(file);
  const index = value.lastIndexOf("/");
  return index > 0 ? value.slice(0, index) : "";
}

function uploadRelativePath(file: File) {
  const relativePath = (file as File & { webkitRelativePath?: string }).webkitRelativePath?.trim();
  return relativePath || "";
}

function uploadDisplayPath(file: File) {
  return uploadRelativePath(file) || file.name;
}

function createFileTreeNode<T extends TreeFile>(name: string, path: string): FileTreeNode<T> {
  return {
    name,
    path,
    folders: [],
    files: [],
    file_count: 0,
    total_bytes: 0
  };
}

function buildFileTree<T extends TreeFile>(files: T[], sortMode: "name" | "size") {
  const root = createFileTreeNode<T>("", "");
  files.forEach((file) => {
    const segments = fileDisplayPath(file).split("/").map((segment) => segment.trim()).filter(Boolean);
    segments.pop();
    let cursor = root;
    segments.forEach((segment) => {
      const nextPath = cursor.path ? `${cursor.path}/${segment}` : segment;
      let child = cursor.folders.find((folder) => folder.path === nextPath);
      if (!child) {
        child = createFileTreeNode<T>(segment, nextPath);
        cursor.folders.push(child);
      }
      cursor = child;
    });
    cursor.files.push(file);
  });
  summarizeFileTree(root, sortMode);
  return root;
}

function summarizeFileTree<T extends TreeFile>(node: FileTreeNode<T>, sortMode: "name" | "size") {
  node.folders.forEach((folder) => summarizeFileTree(folder, sortMode));
  node.folders.sort((left, right) => left.name.localeCompare(right.name, "ru"));
  node.files.sort((left, right) => {
    if (sortMode === "size") {
      const sizeDelta = right.size_bytes - left.size_bytes;
      if (sizeDelta !== 0) {
        return sizeDelta;
      }
    }
    return left.name.localeCompare(right.name, "ru");
  });
  const childFileCount = node.folders.reduce((total, folder) => total + folder.file_count, 0);
  const childBytes = node.folders.reduce((total, folder) => total + folder.total_bytes, 0);
  node.file_count = node.files.length + childFileCount;
  node.total_bytes = node.files.reduce((total, file) => total + file.size_bytes, 0) + childBytes;
}

function FileTree<T extends TreeFile>({
  tree,
  expandedFolders,
  onToggleFolder,
  renderFile
}: {
  tree: FileTreeNode<T>;
  expandedFolders: Record<string, boolean>;
  onToggleFolder: (folderPath: string) => void;
  renderFile: (file: T) => React.ReactNode;
}) {
  return (
    <div className="archive-file-tree">
      {tree.folders.map((folder) => (
        <FileTreeNodeView
          key={folder.path}
          node={folder}
          depth={0}
          expandedFolders={expandedFolders}
          onToggleFolder={onToggleFolder}
          renderFile={renderFile}
        />
      ))}
      {tree.files.map((file) => (
        <div className="archive-tree-file" style={treeDepthStyle(0)} key={file.id}>
          {renderFile(file)}
        </div>
      ))}
    </div>
  );
}

function FileTreeNodeView<T extends TreeFile>({
  node,
  depth,
  expandedFolders,
  onToggleFolder,
  renderFile
}: {
  node: FileTreeNode<T>;
  depth: number;
  expandedFolders: Record<string, boolean>;
  onToggleFolder: (folderPath: string) => void;
  renderFile: (file: T) => React.ReactNode;
}) {
  const expanded = expandedFolders[node.path] !== false;
  return (
    <div className="archive-tree-node">
      <button
        type="button"
        className="archive-tree-folder-row has-tooltip"
        style={treeDepthStyle(depth)}
        aria-expanded={expanded}
        data-tooltip={expanded ? "Collapse subfolder" : "Expand subfolder"}
        onClick={() => onToggleFolder(node.path)}
      >
        <span className="archive-tree-folder-chevron" aria-hidden="true">{expanded ? "▾" : "▸"}</span>
        <strong>{node.name}</strong>
        <span className="archive-tree-folder-meta">{formatFileCount(node.file_count)} / {formatBytes(node.total_bytes)}</span>
      </button>
      {expanded && (
        <div className="archive-tree-children">
          {node.folders.map((folder) => (
            <FileTreeNodeView
              key={folder.path}
              node={folder}
              depth={depth + 1}
              expandedFolders={expandedFolders}
              onToggleFolder={onToggleFolder}
              renderFile={renderFile}
            />
          ))}
          {node.files.map((file) => (
            <div className="archive-tree-file" style={treeDepthStyle(depth + 1)} key={file.id}>
              {renderFile(file)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function treeDepthStyle(depth: number) {
  return { "--tree-depth": depth } as React.CSSProperties;
}

function formatDate(value: string) {
  return new Date(value).toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatAuditDate(value: string) {
  return new Date(value).toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatTime(value: string) {
  return new Date(value).toLocaleString("ru-RU", {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatTTLCountdown(seconds: number) {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(safeSeconds / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const rest = safeSeconds % 60;
  const minuteText = hours > 0 ? String(minutes).padStart(2, "0") : String(minutes);
  const secondText = String(rest).padStart(2, "0");
  if (hours > 0) {
    return `${hours}:${minuteText}:${secondText}`;
  }
  return `${minuteText}:${secondText}`;
}

function folderTTLStateClass(seconds: number | null) {
  if (seconds === null) {
    return "";
  }
  if (seconds <= 0) {
    return "tag-danger ttl-expired";
  }
  if (seconds <= 60) {
    return "tag-danger ttl-critical";
  }
  if (seconds <= 300) {
    return "tag-warn ttl-warning";
  }
  return "tag-ok ttl-active";
}

function folderSessionRowClass(seconds: number | null) {
  if (seconds === null) {
    return "";
  }
  if (seconds <= 0) {
    return "folder-session-expired";
  }
  if (seconds <= 60) {
    return "folder-session-critical";
  }
  if (seconds <= 300) {
    return "folder-session-warning";
  }
  return "folder-session-active";
}

function ttlTickMarker(seconds: number) {
  if (seconds <= 0) {
    return "expired";
  }
  if (seconds <= TTL_TICK_WARNING_SECONDS) {
    return String(Math.max(1, Math.ceil(seconds)));
  }
  return "";
}

function playTTLWarningTone(kind: "tick" | "expired") {
  const AudioContextConstructor = window.AudioContext ?? (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AudioContextConstructor) {
    return;
  }

  try {
    const context = new AudioContextConstructor();
    const startTone = () => {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      const start = context.currentTime;
      const duration = kind === "expired" ? 0.22 : 0.045;
      oscillator.type = kind === "expired" ? "sine" : "square";
      oscillator.frequency.setValueAtTime(kind === "expired" ? 440 : 1320, start);
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(kind === "expired" ? 0.12 : 0.055, start + 0.008);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(start);
      oscillator.stop(start + duration + 0.02);
      oscillator.onended = () => {
        void context.close().catch(() => undefined);
      };
    };

    if (context.state === "suspended") {
      void context.resume().then(startTone).catch(() => {
        void context.close().catch(() => undefined);
      });
      return;
    }
    startTone();
  } catch {
    // The browser may block audio without a user gesture; the visual warning remains.
  }
}

function copyTextFallback(value: string): void {
  let handled = false;
  const handleCopy = (event: ClipboardEvent) => {
    if (!event.clipboardData) {
      return;
    }
    event.clipboardData.setData("text/plain", value);
    event.preventDefault();
    handled = true;
  };
  document.addEventListener("copy", handleCopy);
  try {
    if (document.execCommand("copy") || handled) {
      return;
    }
  } finally {
    document.removeEventListener("copy", handleCopy);
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    if (!document.execCommand("copy")) {
      throw new Error("copy_command_failed");
    }
  } finally {
    textarea.remove();
  }
}

async function copyTextToClipboard(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // HTTP/LAN deployments and some embedded browsers may reject the Clipboard API.
    }
  }
  copyTextFallback(value);
}

function formatTerminalTime(value: string) {
  return new Date(value).toLocaleTimeString("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function terminalSourceLabel(source: string) {
  if (source === "proxy") {
    return "gateway";
  }
  if (source === "asic") {
    return "node";
  }
  if (source === "client") {
    return "client";
  }
  if (source === "terminal") {
    return "terminal";
  }
  return source;
}

function formatPower(value: number) {
  return `${trimNumber(value)} TH/s`;
}

function formatWork(value: number) {
  return `${trimNumber(value)} TH`;
}

function formatDurationSeconds(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return "-";
  }
  if (value < 1) {
    return `${Math.round(value * 1000)} ms`;
  }
  if (value < 60) {
    return `${trimNumber(value)} sec`;
  }
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  return seconds > 0 ? `${minutes} min ${seconds} sec` : `${minutes} min`;
}

function progressPercent(job: Pick<PowJob, "valid_work_th" | "required_work_th">) {
  if (job.required_work_th <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.floor((job.valid_work_th / job.required_work_th) * 100)));
}

function shortHash(value: string) {
  if (value.length <= 24) {
    return value;
  }
  return `${value.slice(0, 12)}...${value.slice(-10)}`;
}

async function sha256File(file: File) {
  if (!window.crypto?.subtle) {
    throw new Error("crypto_subtle_unavailable");
  }
  const buffer = await file.arrayBuffer();
  const digest = await window.crypto.subtle.digest("SHA-256", buffer);
  return arrayBufferToHex(digest);
}

function arrayBufferToHex(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fileVerificationTooltip(verification: FileVerification) {
  const checkedAt = formatDate(verification.checked_at);
  const state = fileVerificationButtonLabel(verification);
  if (verification.checked_sha256) {
    return `${state}; ${verification.checked_name}; SHA-256 ${shortHash(verification.checked_sha256)}; ${checkedAt}`;
  }
  return `${state}; ${verification.checked_name}; ${checkedAt}`;
}

function fileVerificationButtonLabel(verification?: FileVerification) {
  if (!verification) {
    return "verify";
  }
  if (verification.status === "checking") {
    return "checking";
  }
  if (verification.status === "matched") {
    return "matched";
  }
  if (verification.status === "mismatched") {
    return "mismatched";
  }
  return "error";
}

function shortJSON(value: unknown) {
  const raw = JSON.stringify(value ?? {});
  if (raw.length <= 180) {
    return raw;
  }
  return `${raw.slice(0, 177)}...`;
}

function trimNumber(value: number) {
  if (!Number.isFinite(value)) {
    return "0";
  }
  if (value >= 100) {
    return value.toFixed(0);
  }
  if (value >= 1) {
    return value.toFixed(2).replace(/\.?0+$/, "");
  }
  return value.toFixed(6).replace(/\.?0+$/, "");
}

type PoWStatus = PowJob["status"] | ClientPowJob["status"];

function jobStatusLabel(status: PoWStatus) {
  if (status === "queued") {
    return "queued";
  }
  if (status === "running") {
    return "checking";
  }
  if (status === "succeeded") {
    return "succeeded";
  }
  if (status === "timeout") {
    return "timeout";
  }
  if (status === "canceled") {
    return "canceled";
  }
  return "error";
}

function accessStatusLabel(activeSession?: AccessSession, job?: ClientPowJob) {
  if (activeSession) {
    return "Open";
  }
  if (!job) {
    return "Closed";
  }
  if (job.status === "queued" || job.status === "running") {
    return "Verification running";
  }
  if (job.status === "succeeded") {
    return "Closed";
  }
  if (job.status === "timeout") {
    return "Insufficient";
  }
  if (job.status === "failed") {
    return "Error";
  }
  if (job.status === "canceled") {
    return "Closed";
  }
  return "Closed";
}

function accessStatusClass(activeSession?: AccessSession, job?: ClientPowJob) {
  if (activeSession) {
    return "access-status-token access-status-active";
  }
  if (job?.status === "queued" || job?.status === "running") {
    return "access-status-token access-status-running";
  }
  if (job?.status === "timeout" || job?.status === "failed") {
    return "access-status-token access-status-danger";
  }
  return "access-status-token";
}

function accessStatusTooltip(activeSession?: AccessSession, job?: ClientPowJob) {
  if (activeSession) {
    return "Folder is open. Files can be read and downloaded until expiration.";
  }
  if (!job) {
    return "Folder is closed. Click Open if you have access permission.";
  }
  if (job.status === "queued" || job.status === "running") {
    return "Verification is running. Exact verification parameters are not shown on the client page.";
  }
  if (job.status === "succeeded") {
    return "Verification previously succeeded, but there is no active TTL session anymore. The folder is closed again.";
  }
  if (job.status === "timeout") {
    return "Verification failed.";
  }
  if (job.status === "failed") {
    return "Verification ended with an error.";
  }
  if (job.status === "canceled") {
    return "Access was closed or canceled.";
  }
  return "Folder closed.";
}

function powIndicatorState(activeSession?: AccessSession, job?: ClientPowJob) {
  if (activeSession) {
    return "accepted";
  }
  if (job?.status === "queued" || job?.status === "running") {
    return "running";
  }
  if (job?.status === "timeout" || job?.status === "failed") {
    return "rejected";
  }
  if (job?.status === "canceled") {
    return "closed";
  }
  return "idle";
}

function powIndicatorTooltip(activeSession?: AccessSession, job?: ClientPowJob) {
  if (activeSession) {
    return "Verification is sufficient.";
  }
  if (job?.status === "succeeded") {
    return "Verification was sufficient earlier, but there is no active TTL session anymore.";
  }
  if (job?.status === "queued" || job?.status === "running") {
    return "Verification is running. The indicator shows only state, not exact hashrate parameters.";
  }
  if (job?.status === "timeout" || job?.status === "failed") {
    return "Verification failed.";
  }
  if (job?.status === "canceled") {
    return "Access closed.";
  }
  return "Verification has not started.";
}

function accessActionTooltip(activeSession: AccessSession | undefined, job: ClientPowJob | undefined, nodeLinkOK: boolean) {
  if (activeSession) {
    return "Close the active TTL access session for the selected folder.";
  }
  if (job) {
    return "Cancel the current access attempt for the selected folder.";
  }
  if (!nodeLinkOK) {
    return "Open is unavailable: no compute node link.";
  }
  return "Open the selected folder through Proof-of-Work. On success, a TTL session opens.";
}

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element not found");
}

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
