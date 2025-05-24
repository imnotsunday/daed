// api.js

const baseUrl = 'https://t2tqpk6s0k.execute-api.us-east-1.amazonaws.com/prod'; // ใส่ของคุณตรงนี้

export async function apiGet(path) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer ' + token,
    },
  });
  return res.json();
}

export async function apiPost(path, data) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function apiPut(path, data) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'PUT',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function apiDelete(path) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + token,
    },
  });
  return res.json();
}

export function storeTemp(key, data) {
  localStorage.setItem(key, JSON.stringify(data));
}

export function loadTemp(key) {
  const data = localStorage.getItem(key);
  return data ? JSON.parse(data) : null;
}

export function clearTemp(key) {
  localStorage.removeItem(key);
}