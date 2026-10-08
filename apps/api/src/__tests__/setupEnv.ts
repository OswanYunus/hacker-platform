process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-characters-long";
process.env.MASTER_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
