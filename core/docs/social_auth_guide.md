# 🔐 Social Authentication Implementation Guide

**(Google • GitHub • LinkedIn)**

## ✅ Recommended Approach (Industry Standard)

Use **OAuth 2.0** with a backend-controlled authentication flow.

👉 **DO NOT** authenticate users directly from frontend only  
👉 **ALWAYS** handle OAuth tokens securely on the backend

---

## 🏗️ Architecture Overview

```mermaid
graph TD
    Client[Frontend (React)] -->|Login Request| Backend[Backend (Node.js/Express)]
    Backend -->|Redirect| Provider[OAuth Provider (Google/GitHub/LinkedIn)]
    Provider -->|Callback w/ Code| Backend
    Backend -->|Exchange Code for Token| Provider
    Provider -->|Access Token| Backend
    Backend -->|Fetch User Profile| Provider
    Backend -->|Validate & Create JWT| Backend
    Backend -->|Return JWT| Client
```

---

## 🧰 Best Tools (Use This)

### Backend

*   **Node.js + Express**
*   **Passport.js** (OAuth handling)
*   **passport-google-oauth20**
*   **passport-github2**
*   **passport-linkedin-oauth2**
*   **JWT** (jsonwebtoken)

### Frontend

*   React
*   Axios
*   Redirect-based login buttons

---

# 🔵 GOOGLE AUTHENTICATION

## 1️⃣ Create Google OAuth App

1.  Go to **Google Cloud Console**
2.  Create Project
3.  Enable **Google Identity API**
4.  Create **OAuth 2.0 Client ID**
5.  Set Redirect URI:
    ```
    http://localhost:5000/auth/google/callback
    ```

---

## 2️⃣ Backend Setup (Google)

Install:
```bash
npm install passport passport-google-oauth20
```

Configure strategy:
```js
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));
```

Routes:
```js
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    // create JWT and redirect
  }
);
```

---

# 🟣 GITHUB AUTHENTICATION

## 1️⃣ Create GitHub OAuth App

1.  GitHub → Settings → Developer Settings
2.  OAuth Apps → New App
3.  Callback URL:
    ```
    http://localhost:5000/auth/github/callback
    ```

---

## 2️⃣ Backend Setup (GitHub)

Install:
```bash
npm install passport-github2
```

Strategy:
```js
passport.use(new GitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "/auth/github/callback"
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));
```

Routes:
```js
app.get("/auth/github",
  passport.authenticate("github")
);

app.get("/auth/github/callback",
  passport.authenticate("github", { session: false }),
  (req, res) => {
    // generate JWT
  }
);
```

---

# 🔷 LINKEDIN AUTHENTICATION

## 1️⃣ Create LinkedIn App

1.  LinkedIn Developers Portal
2.  Create App
3.  Enable **Sign In with LinkedIn**
4.  Redirect URI:
    ```
    http://localhost:5000/auth/linkedin/callback
    ```

---

## 2️⃣ Backend Setup (LinkedIn)

Install:
```bash
npm install passport-linkedin-oauth2
```

Strategy:
```js
passport.use(new LinkedInStrategy({
  clientID: LINKEDIN_CLIENT_ID,
  clientSecret: LINKEDIN_CLIENT_SECRET,
  callbackURL: "/auth/linkedin/callback",
  scope: ["r_liteprofile", "r_emailaddress"]
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));
```

Routes:
```js
app.get("/auth/linkedin",
  passport.authenticate("linkedin")
);

app.get("/auth/linkedin/callback",
  passport.authenticate("linkedin", { session: false }),
  (req, res) => {
    // generate JWT
  }
);
```

---

# 🔑 JWT TOKEN CREATION (COMMON FOR ALL)

```js
const token = jwt.sign(
  { id: user.id, email: user.email },
  process.env.JWT_SECRET,
  { expiresIn: "1d" }
);
```

Send token to frontend via redirect or JSON response.

---

# 🎨 FRONTEND IMPLEMENTATION (React)

Login buttons:
```jsx
<button onClick={() => window.open("http://localhost:5000/auth/google", "_self")}>
  Login with Google
</button>

<button onClick={() => window.open("http://localhost:5000/auth/github", "_self")}>
  Login with GitHub
</button>

<button onClick={() => window.open("http://localhost:5000/auth/linkedin", "_self")}>
  Login with LinkedIn
</button>
```

Store token:
```js
localStorage.setItem("token", token);
```

---

# 🔐 Security Best Practices (IMPORTANT)

*   Never expose client secrets in frontend
*   Always validate OAuth response on backend
*   Use HTTPS in production
*   Use JWT expiry + refresh tokens
*   Restrict callback URLs
*   Implement Rate Limiting on Auth Endpoints
