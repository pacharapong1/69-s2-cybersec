'use strict';

// อ่าน reset code จาก JSON ของ Mailhog API (stdin) ใช้คู่กับ forgot-token.sh / reset-token.sh
// - admin email: รูป link  ?code=<url-encoded expires_ms:%3Axxx>  (quoted-printable =3D)
// - user email:  ตัวอักษรล้วน    <expires_ms>:<hex128>
// Mailhog คืน messages ใหม่สุดก่อนเสมอ -> ใช้ index 0
let data = '';
process.stdin.on('data', (c) => (data += c));
process.stdin.on('end', () => {
  try {
    const arr = JSON.parse(data);
    const msgs = Array.isArray(arr) ? arr : [arr];
    const body = (msgs[0] || {}).Content?.Body || '';
    const flattened = body.replace(/=\r?\n/g, '').replace(/=3D/g, '=');
    const decoded = decodeURIComponent(flattened);
    const link = decoded.match(/code=([0-9]{13}:[A-Za-z0-9_-]+)/);
    const plain = flattened.match(/([0-9]{13}:[0-9a-f]{128})/);
    process.stdout.write((link ? link[1] : null) || (plain ? plain[1] : ''));
  } catch (e) {
    process.stdout.write('');
  }
});