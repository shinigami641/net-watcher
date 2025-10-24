import axios from 'axios';

const BASE_URL = 'http://localhost:4000/api';

export const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const API_ENDPOINTS = {
  ACTIVE_INTERFACE: '/active-interface',
  IP_ADDR: '/ip-addr',
  SCAN_IP: '/scan-ip',
  TRAFFIC: '/traffict',
  TRAFFIC_STOP: '/traffict-stop',
  TRAFFIC_STATUS: '/traffict-status',
  TRAFFIC_STOP_ALL: '/traffict-stop-all',
};

export const WS_URL = 'http://127.0.0.1:4000/notifications';