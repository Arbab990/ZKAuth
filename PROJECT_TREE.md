# ZKAuth Project Tree

```text
ZKAuth/
├── .github/
│   └── workflows/
│       └── test.yml
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── admin_routes.py
│   │   │   ├── auth_routes.py
│   │   │   └── token_routes.py
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── audit_chain.py
│   │   │   ├── srp_core.py
│   │   │   └── token_signer.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── auth_event.py
│   │   │   ├── session.py
│   │   │   └── user.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── audit_service.py
│   │   │   ├── login_service.py
│   │   │   └── registration_service.py
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── database.py
│   │   └── generate_keys.py
│   ├── keys/
│   │   └── .gitkeep
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_audit_chain.py
│   │   ├── test_auth_routes.py
│   │   ├── test_health.py
│   │   ├── test_security_paths.py
│   │   ├── test_srp_core.py
│   │   └── test_token_signer.py
│   ├── .env.example
│   └── requirements.txt
│   └── pytest.ini

├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── zkauth.js
│   │   ├── pages/
│   │   │   ├── Login.jsx
│   │   │   └── Register.jsx
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── .env.example
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   └── vite.config.js
├── sdk-js/
│   ├── src/
│   │   ├── client.js
│   │   ├── index.js
│   │   └── srpCore.js
│   ├── tests/
│   │   └── sdk.test.js
│   ├── package.json
│   ├── package-lock.json
│   └── README.md
├── sdk-python/
│   ├── tests/
│   │   └── test_sdk_flow.py
│   ├── zkauth_client/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   └── srp_client.py
│   ├── zkauth_client.egg-info/
│   │   ├── dependency_links.txt
│   │   ├── PKG-INFO
│   │   ├── requires.txt
│   │   ├── SOURCES.txt
│   │   └── top_level.txt
│   ├── pyproject.toml
│   └── README.md
├── .gitignore
├── context.md
├── PROJECT_TREE.md
├── README.md
└── ROADMAP.md
```

> Generated from the current workspace contents. Generated dependencies and cache directories (such as `.git`, `.npm-cache`, and `node_modules`) are omitted.
