import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
});

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("noc_token");
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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

export default api;
