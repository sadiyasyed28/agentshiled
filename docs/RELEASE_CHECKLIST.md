# AgentShield SDK Release Checklist

This document defines the formal checklist and release procedures for publishing the **AgentShield** Python SDK to PyPI and GitHub Releases.

> [!IMPORTANT]
> **Safety Rule**: Never publish to PyPI, create a public GitHub release, merge release branches, or deploy without explicit human authorization.

---

## 1. Pre-Release Verification Checklist

Perform these checks sequentially before publishing any release candidate:

### A. Repository Hygiene & Git State
- [ ] Working tree is clean (`git status` reports no untracked or uncommitted changes).
- [ ] Working on the intended release branch (e.g., `feature/secure-config-management` or `main`).
- [ ] All commits are pushed to the remote repository.
- [ ] `git diff --check` passes with zero whitespace or line-ending errors.

### B. Version & Metadata Consistency
- [ ] `pyproject.toml` version matches release version: `version = "0.1.0"`
- [ ] `src/agentshield/__init__.py` defines `__version__ = "0.1.0"`
- [ ] `CHANGELOG.md` contains an entry for `[0.1.0]` with date and release notes.
- [ ] License declaration matches: `license = { text = "MIT" }` in `pyproject.toml` and `LICENSE` is MIT.
- [ ] Classifiers in `pyproject.toml` accurately reflect supported Python versions (3.11, 3.12, 3.13, 3.14).
- [ ] Project URLs in `pyproject.toml` are valid and reachable.

### C. Security & Secret Leak Audit
- [ ] Verify no `.env` or credential files are tracked:
  ```bash
  git ls-files | grep -E '\.env$|\.pem$|\.key$|\.db$'
  ```
  *(Must return empty)*
- [ ] Run configuration validator to confirm secrets are redacted:
  ```bash
  python -m agentshield.config_validation
  ```

### D. Automated Test Verification
- [ ] Core backend test suite:
  ```bash
  pytest -v --tb=short
  ```
- [ ] Adversarial and security tests:
  ```bash
  pytest tests/test_adversarial_validation.py tests/test_security_hardening.py -v
  ```
- [ ] Production readiness and concurrency tests:
  ```bash
  pytest tests/test_production_readiness.py tests/test_tenant_isolation.py -v
  ```
- [ ] Frontend tests and production bundle:
  ```bash
  npm test
  npm run build
  npm --prefix frontend test
  npm --prefix frontend run build
  ```

---

## 2. Package Build & Artifact Inspection

### A. Clean Old Distribution Artifacts
```bash
# Clean dist directory before building
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
# Or on Unix: rm -rf dist/
```

### B. Build Source Distribution and Wheel
```bash
python -m build
```

### C. Verify Archive Contents
Verify that **only** `src/agentshield` files are packaged and that frontend sources, tests, node_modules, and docs are excluded:
```bash
# Inspect wheel contents
python -m zipfile -l dist/*.whl

# Inspect source distribution contents
python -m tarfile -l dist/*.tar.gz
```

*Confirm that:*
- No `frontend/`, `node_modules/`, `dist/assets/`, or `package.json` exist in the wheel.
- `agentshield-0.1.0.dist-info/METADATA` contains valid descriptions and classifiers.

### D. Run Twine Package Validation
```bash
python -m twine check dist/*.whl dist/*.tar.gz
```
*(Must output `PASSED` for all distribution files with 0 warnings or errors)*

---

## 3. Clean-Environment Smoke Testing

Validate the built wheel in an isolated, minimal environment to guarantee standalone operation:

```bash
# Create a temporary virtual environment
python -m venv .venv_release_smoke

# Windows:
.\.venv_release_smoke\Scripts\Activate.ps1
# Linux / macOS:
# source .venv_release_smoke/bin/activate

# Upgrade pip and install the newly built wheel ONLY
pip install (Get-Item dist/*.whl).FullName

# Verify core SDK functionality and minimal dependencies:
python -c "
import agentshield
print('Version:', agentshield.__version__)
from agentshield import Shield, PolicyConfiguration, Decision, DecisionValue, RiskLevel

policy = PolicyConfiguration.from_dict({
    'agents': {'bot': {'allowed_tools': ['ping']}},
    'tools': {'ping': {}},
})
shield = Shield(policy=policy)
shield.registry.register('ping', lambda args: {'pong': True})
res = shield.execute(agent='bot', tool='ping', arguments={})
assert res.decision.decision == DecisionValue.ALLOW
assert res.tool_result == {'pong': True}
print('Standalone Core SDK Smoke Test Passed!')
"

# Verify optional extras produce actionable installation guidance:
python -c "
import pytest
import agentshield

# YAML without PyYAML
try:
    agentshield.PolicyConfiguration.from_yaml('dummy.yaml')
except ImportError as e:
    assert 'agentshield[yaml]' in str(e)
    print('YAML extra error message verified.')

# LangChain without langchain-core
try:
    _ = agentshield.protect_langchain_tool
except ImportError as e:
    assert 'agentshield[langchain]' in str(e)
    print('LangChain extra error message verified.')

# CrewAI without crewai
try:
    _ = agentshield.protect_crewai_tool
except ImportError as e:
    assert 'agentshield[crewai]' in str(e)
    print('CrewAI extra error message verified.')
"

# Deactivate and clean up smoke environment
deactivate
Remove-Item -Recurse -Force .venv_release_smoke
```

---

## 4. Release Execution (Manual Approval Required)

> [!CAUTION]
> Obtain explicit approval before proceeding with this section.

### Option A: PyPI Trusted Publishing via GitHub Actions (Recommended)
1. Ensure the PyPI project `agentshield` has GitHub Actions Trusted Publishing configured for:
   - Owner: `sadiyasyed28`
   - Repository: `agentshiled`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. Navigate to GitHub Actions → **Release SDK to PyPI**.
3. Click **Run workflow**:
   - `dry_run`: `false`
   - `confirm`: `RELEASE-0.1.0`
4. The workflow will build, validate with `twine check`, smoke test the wheel, and publish to PyPI using short-lived OIDC tokens.

### Option B: Manual Upload via Twine (Emergency / Direct)
If GitHub Actions OIDC is not configured:
```bash
# Requires PYPI_API_TOKEN environment variable or interactive prompt:
python -m twine upload dist/*.whl dist/*.tar.gz
```

### Git Tagging
Once publishing succeeds:
```bash
git tag -a v0.1.0 -m "Release AgentShield v0.1.0"
git push origin v0.1.0
```

---

## 5. Post-Release Verification

- [ ] Check PyPI page: `https://pypi.org/project/agentshield/0.1.0/`
- [ ] Verify README renders properly on PyPI with working links and syntax highlighting.
- [ ] Test installation from PyPI in a fresh environment:
  ```bash
  python -m venv .venv_pypi_test
  .\.venv_pypi_test\Scripts\pip install agentshield
  .\.venv_pypi_test\Scripts\python -c "import agentshield; print(agentshield.__version__)"
  Remove-Item -Recurse -Force .venv_pypi_test
  ```
- [ ] Create GitHub Release corresponding to tag `v0.1.0` with release notes from `CHANGELOG.md`.
