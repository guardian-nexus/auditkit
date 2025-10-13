#!/bin/bash
# Path: scripts/setup-hooks.sh

set -e

echo "🔧 Installing git hooks..."

cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e

echo "🔍 Pre-commit checks..."

# Check for hardcoded paths
if grep -r "dijital\|/home/dijital" --include="*.go" --exclude-dir=".git" . 2>/dev/null; then
    echo "❌ Found hardcoded paths!"
    exit 1
fi

# Check formatting
unformatted=$(gofmt -l . 2>/dev/null | grep -v "vendor/" || true)
if [ -n "$unformatted" ]; then
    echo "❌ Code not formatted. Run: gofmt -w ."
    exit 1
fi

# Check build
if ! go build -o /tmp/auditkit-check ./cmd/auditkit 2>/dev/null; then
    echo "❌ Build failed!"
    exit 1
fi
rm -f /tmp/auditkit-check

# Tidy go.mod
go mod tidy
if ! git diff --exit-code go.mod go.sum >/dev/null 2>&1; then
    git add go.mod go.sum
fi

echo "✅ Checks passed"
EOF

chmod +x .git/hooks/pre-commit

echo "✅ Git hooks installed!"
echo ""
echo "Test it: echo 'bad /home/dijital' > test.go && git add test.go && git commit -m test"
echo "(It should fail. Then run: rm test.go)"
