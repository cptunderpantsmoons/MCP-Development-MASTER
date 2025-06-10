# Pull Request

## 📋 Summary
Provide a brief description of the changes in this PR.

## 🎯 Type of Change
What type of change does this PR introduce? (Check all that apply)
- [ ] 🐛 **Bug fix** (non-breaking change that fixes an issue)
- [ ] ✨ **New feature** (non-breaking change that adds functionality)
- [ ] 💥 **Breaking change** (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 **Documentation** (documentation only changes)
- [ ] 🎨 **Style** (formatting, missing semicolons, etc; no code change)
- [ ] ♻️ **Refactoring** (code change that neither fixes a bug nor adds a feature)
- [ ] ⚡ **Performance** (code change that improves performance)
- [ ] ✅ **Test** (adding missing tests or correcting existing tests)
- [ ] 🔧 **Build** (changes that affect the build system or external dependencies)
- [ ] 👷 **CI** (changes to CI configuration files and scripts)
- [ ] 🔒 **Security** (security improvements or fixes)

## 🔗 Related Issues
Closes #[issue number]
Fixes #[issue number]
Relates to #[issue number]

## 📝 Description
Provide a detailed description of the changes:

### What was changed?
- Change 1
- Change 2
- Change 3

### Why was it changed?
Explain the motivation behind these changes.

### How was it changed?
Describe the approach you took to implement these changes.

## 🧪 Testing
Describe the testing you've performed:

### Test Cases
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] End-to-end tests added/updated
- [ ] Manual testing performed

### Test Coverage
- [ ] New code is covered by tests
- [ ] Existing tests pass
- [ ] Coverage percentage maintained or improved

### Testing Commands
```bash
# Commands used to test the changes
pytest tests/
coverage run -m pytest
```

## 🔒 Security Considerations
If this PR has security implications:

- [ ] **No security impact** - This change doesn't affect security
- [ ] **Security reviewed** - Security implications have been considered
- [ ] **Credentials handled securely** - No hardcoded secrets or improper credential handling
- [ ] **Input validation added** - User inputs are properly validated
- [ ] **Authorization checked** - Proper access controls are in place
- [ ] **Dependencies secured** - New dependencies are from trusted sources

### Security Checklist (if applicable)
- [ ] Secrets are not hardcoded
- [ ] Input validation is implemented
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] Authentication/authorization checks
- [ ] Secure communication (HTTPS/TLS)
- [ ] Proper error handling (no sensitive info in errors)

## 🏗️ Infrastructure/Deployment
If this PR affects infrastructure or deployment:

- [ ] **No infrastructure changes**
- [ ] **Docker changes** - Dockerfile or docker-compose updated
- [ ] **Kubernetes changes** - K8s manifests updated
- [ ] **Database changes** - Schema migrations included
- [ ] **Configuration changes** - New config options documented
- [ ] **Environment variables** - New env vars documented

## 📖 Documentation
Documentation changes made:

- [ ] **No documentation needed**
- [ ] **README updated**
- [ ] **API documentation updated**
- [ ] **Configuration documentation updated**
- [ ] **Deployment documentation updated**
- [ ] **Changelog updated**
- [ ] **Code comments added/updated**

## 🔄 Backward Compatibility
- [ ] **Fully backward compatible** - No breaking changes
- [ ] **Breaking changes documented** - Migration guide provided
- [ ] **Deprecation warnings added** - For features being removed
- [ ] **Version bump required** - Major/minor version change needed

## 📊 Performance Impact
- [ ] **No performance impact**
- [ ] **Performance improved** - Benchmarks provided below
- [ ] **Performance regression possible** - Justified by benefits
- [ ] **Performance testing required** - Load tests recommended

### Performance Metrics (if applicable)
```
Before: [metrics]
After: [metrics]
Improvement: [percentage or description]
```

## 🌐 Cloud Provider Impact
Which cloud providers are affected by this change?
- [ ] AWS
- [ ] Azure
- [ ] GCP
- [ ] Kubernetes
- [ ] All providers
- [ ] None

## 🛠️ Tool Integration Impact
Which security tools are affected?
- [ ] Prowler
- [ ] Checkov
- [ ] Trivy
- [ ] Kube-hunter
- [ ] Scout Suite
- [ ] Custom tools
- [ ] All tools
- [ ] None

## 📸 Screenshots/Logs
If applicable, add screenshots or log outputs:

### Before
```
Previous behavior/output
```

### After
```
New behavior/output
```

## ✅ Pre-submission Checklist
- [ ] I have read the [CONTRIBUTING](../CONTRIBUTING.md) document
- [ ] My code follows the code style of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## 🚀 Deployment Notes
Special instructions for deploying this change:

- [ ] **Standard deployment** - No special steps required
- [ ] **Database migration required** - Run migrations before deployment
- [ ] **Configuration update required** - Update config files
- [ ] **Environment variables required** - Set new env vars
- [ ] **Service restart required** - Restart specific services
- [ ] **Cache invalidation required** - Clear application caches

### Deployment Steps
1. Step 1
2. Step 2
3. Step 3

## 🔍 Review Focus Areas
Please pay special attention to these areas during review:

- [ ] Security implications
- [ ] Performance impact
- [ ] Error handling
- [ ] Configuration changes
- [ ] Database queries
- [ ] API changes
- [ ] Authentication/authorization
- [ ] Input validation
- [ ] Logging and monitoring

## 📋 Additional Notes
Any additional information that reviewers should know:

---

## 👥 Reviewers
- @security-team (for security-related changes)
- @devops-team (for infrastructure changes)
- @maintainer1
- @maintainer2

**Thank you for contributing to the Cloud Security MCP Server! 🚀**
