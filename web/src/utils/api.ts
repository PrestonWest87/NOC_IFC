import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
});

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("noc_token");
  if (token) {
    config.params = { ...config.params, token };
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem("noc_token");
      sessionStorage.removeItem("noc_user");
      window.location.hash = "#/login";
    }
    return Promise.reject(err);
  }
);

export default api;
