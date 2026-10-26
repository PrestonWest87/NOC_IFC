import axios from "axios";

/** Same-origin `/api/v1` client with Bearer attachment and 401/403 UI events. */
const api = axios.create({
  baseURL: "/api/v1",
});

/** Attach the current tab's opaque session token to each protected request. */
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("noc_token");
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/** Clear auth only on 401; surface structured 403 feedback while retaining the session. */
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem("noc_token");
      sessionStorage.removeItem("noc_user");
      window.dispatchEvent(new Event("noc:unauthorized"));
      window.location.hash = "#/login";
    } else if (err.response?.status === 403) {
      const detail = err.response?.data?.detail;
      window.dispatchEvent(new CustomEvent("noc:permission-denied", { detail }));
      if (detail && typeof detail === "object" && typeof detail.message === "string") {
        err.response.data.detail = detail.message;
      }
    }
    return Promise.reject(err);
  }
);

/** Convert structured auth, permission, and network failures into operator-facing text. */
export function getApiErrorMessage(error: any, fallback = "The request could not be completed."): string {
  const status = error?.response?.status;
  const detail = error?.response?.data?.detail;
  if (status === 401) return "Your session has expired. Sign in again.";
  if (status === 403) {
    if (detail && typeof detail === "object") {
      return detail.message || (detail.permission
        ? `You do not have permission to ${detail.permission}. Ask an administrator to grant it.`
        : "You do not have permission to perform this action.");
    }
    return typeof detail === "string" && detail
      ? detail
      : "You do not have permission to perform this action. Ask an administrator for access.";
  }
  if (typeof detail === "string" && detail) return detail;
  if (detail && typeof detail === "object" && detail.message) return detail.message;
  if (!error?.response) return "Unable to reach the server. Check your connection and try again.";
  return error?.message || fallback;
}

/** Shared Axios instance used by pages, hooks, and components. */
export default api;
