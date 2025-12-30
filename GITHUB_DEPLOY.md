# 🚀 Quick GitHub Deployment Commands

## Step 1: Create GitHub Repository

Visit: https://github.com/new

- **Repository name**: `ase-security-platform`
- **Description**: "Comprehensive web-based security auditing and vulnerability assessment platform"
- **Visibility**: Choose Public or Private
- **DO NOT** check "Initialize with README"
- Click **Create repository**

---

## Step 2: Push Your Code

Copy your GitHub username, then run these commands:

```bash
# Navigate to your project (if not already there)
cd d:\ase.new\core

# Add GitHub as remote (REPLACE YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/ase-security-platform.git

# Rename branch to main
git branch -M main

# Push to GitHub
git push -u origin main
```

**Example** (replace with your username):
```bash
git remote add origin https://github.com/rajak/ase-security-platform.git
git branch -M main
git push -u origin main
```

---

## Step 3: Verify Upload

Visit your repository:
```
https://github.com/YOUR_USERNAME/ase-security-platform
```

Check:
- ✅ README.md displays on homepage
- ✅ All Python files are present
- ✅ No `users_db.json` or `audit_log.json` (should be excluded)
- ✅ No `.env` file (should be excluded)
- ✅ `.env.example` is present

---

## 🔐 IMPORTANT: Security Actions

### 1. Regenerate API Key
The old API key was in the code, so regenerate it:

1. Go to: https://makersuite.google.com/app/apikey
2. Delete old key: `AIzaSyB_kOeyZY__DXkfb-o4laNo59ClFdNsOkQ`
3. Create new key
4. Save to local `.env` file

### 2. Create Local .env File

```bash
# Copy template
cp .env.example .env

# Edit with your values
notepad .env
```

Add:
```env
GEMINI_API_KEY=your_new_api_key_here
ADMIN_ACCESS_CODE=your_secure_admin_code_here
```

---

## 🌐 Deploy to Streamlit Cloud (Optional)

1. Visit: https://share.streamlit.io
2. Sign in with GitHub
3. Click "New app"
4. Select repository: `ase-security-platform`
5. Main file: `app.py`
6. Click "Deploy"

### Add Secrets in Streamlit Cloud:
In app settings → Secrets, add:
```toml
GEMINI_API_KEY = "your_new_api_key"
ADMIN_ACCESS_CODE = "your_secure_code"
```

Your app will be live at:
```
https://YOUR_USERNAME-ase-security-platform.streamlit.app
```

---

## 🔄 Future Updates

To push changes:
```bash
git add .
git commit -m "Your change description"
git push origin main
```

---

## ❓ Troubleshooting

### Authentication Error
If you get "Permission denied":

**Option 1: Use Personal Access Token**
1. Create token: https://github.com/settings/tokens
2. Generate new token (classic)
3. Select scopes: `repo`
4. Copy token
5. Use in URL:
```bash
git remote set-url origin https://YOUR_TOKEN@github.com/YOUR_USERNAME/ase-security-platform.git
```

**Option 2: Use GitHub CLI**
```bash
gh auth login
# Follow prompts
```

### Already Exists Error
If repository already exists:
```bash
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/your-repo-name.git
git push -u origin main
```

---

## ✅ Done!

Your ASE Security Platform is now on GitHub! 🎉

**Next Steps:**
1. Share repository link with team
2. Add collaborators (Settings → Collaborators)
3. Enable GitHub Actions (optional)
4. Add topics/tags for discoverability
5. Star your own repo! ⭐
