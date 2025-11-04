import axios from 'axios';

export const BASE_URL = 'http://localhost:4000/api';
export const WS_URL = 'http://localhost:4000';

export const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});
