"""Small bundled list of weak HMAC secrets seen in tutorials, defaults and leaks.

It is intentionally short: the goal is a fast smoke test for obviously weak
keys, not a full offline brute force. Use ``--wordlist`` for bigger lists.
"""

WEAK_SECRETS = (
    "secret", "Secret", "SECRET", "secret123", "secretkey", "secret_key", "secret-key", "SecretKey",
    "mysecret", "my_secret", "my-secret", "mysecretkey", "my_secret_key", "mySecretKey", "supersecret",
    "super_secret", "super-secret", "supersecretkey", "topsecret", "s3cr3t", "s3cret", "shhhhh", "shhh",
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret", "your_jwt_secret", "your-secret-key",
    "jwt", "jwt_secret", "jwt-secret", "jwtsecret", "JWT_SECRET", "jwtSecret", "jwt_secret_key",
    "jwtkey", "jwt-key", "token", "tokensecret", "token_secret", "auth", "authsecret", "auth_secret",
    "key", "Key", "KEY", "private", "privatekey", "private_key", "signingkey", "signing_key", "hmac",
    "hmacsecret", "app_secret", "appsecret", "app-secret", "api_secret", "apisecret", "client_secret",
    "password", "Password", "PASSWORD", "password1", "password123", "passw0rd", "Passw0rd", "p@ssw0rd",
    "pass", "passwd", "123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234",
    "111111", "000000", "654321", "qwerty", "qwerty123", "abc123", "abcdef", "abcd1234", "letmein",
    "welcome", "admin", "admin123", "administrator", "root", "toor", "test", "test123", "testing",
    "testsecret", "dev", "development", "devsecret", "prod", "production", "staging", "local",
    "default", "changeme", "change_me", "change-me", "changeit", "CHANGE_ME", "replaceme",
    "example", "sample", "demo", "foobar", "foo", "bar", "baz", "hello", "helloworld", "hello_world",
    "iloveyou", "monkey", "dragon", "master", "login", "guest", "user", "null", "none", "undefined",
    "keyboardcat", "keyboard cat", "shared_secret", "sharedsecret", "server_secret", "session_secret",
    "sessionsecret", "cookie_secret", "nodejs", "express", "django-insecure", "flask", "laravel",
    "rails", "spring", "springboot", "gin", "fastapi", "node", "react", "angular", "vue",
    "a", "aa", "aaa", "x", "xxx", "0", "1", "",
)
