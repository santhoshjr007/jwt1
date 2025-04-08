
const { encrypt, decrypt } = require('./script');

const payload = { userId: 123, role: 'admin' };

const { token, iv } = encrypt(payload);
console.log("Encrypted Token:", token);

const decoded = decrypt(token, iv);
console.log("Decoded Payload:", decoded);
