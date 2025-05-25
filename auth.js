// auth.js

// อ่าน token จาก localStorage
export function getToken() {
  return localStorage.getItem('token');
}

// ถอด JWT payload (ไม่ต้อง verify signature)
export function decodeToken(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = atob(payload);
    return JSON.parse(decoded);
  } catch (err) {
    return null;
  }
}

// ดึง role จาก token
export function getUserRole() {
  const token = getToken();
  if (!token) return null;
  const decoded = decodeToken(token);
  return decoded?.role || null;
}

// ดึง userId จาก token
export function getUserId() {
  const token = getToken();
  if (!token) return null;
  const decoded = decodeToken(token);
  return decoded?.userId || null;
}

// ตรวจว่า role ตรงกับที่กำหนดไหม (ถ้าไม่ → redirect)
export function requireRole(requiredRole) {
  const role = getUserRole();
  if (!role) {
    window.location.href = "login.html"; // ยังไม่ login
  } else if (role !== requiredRole) {
    window.location.href = "unauthorized.html"; // login แล้วแต่ไม่ใช่ role นี้
  }
}

// ออกจากระบบ
export function logout() {
  localStorage.removeItem('token');
  window.location.href = 'login.html';
}

export function getUser() {
  const token = getToken();
  if (!token) return null;
  return decodeToken(token);
}