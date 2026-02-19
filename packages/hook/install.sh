#!/bin/bash
#
# SPEAR Hook Installer for Claude Code
#
# Usage: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash
#

set -e

HOOK_DIR="$HOME/.claude/hooks"
HOOK_FILE="$HOOK_DIR/spear-hook.mjs"
HOOKS_JSON=".claude/hooks.json"

echo "Installing SPEAR Hook for Claude Code..."

# Create hooks directory
mkdir -p "$HOOK_DIR"

# Download hook script
if command -v curl &> /dev/null; then
  curl -fsSL -o "$HOOK_FILE" \
    "https://raw.githubusercontent.com/anthropic-community/spear/main/packages/hook/spear-hook.mjs"
elif command -v wget &> /dev/null; then
  wget -q -O "$HOOK_FILE" \
    "https://raw.githubusercontent.com/anthropic-community/spear/main/packages/hook/spear-hook.mjs"
else
  echo "Error: curl or wget required"
  exit 1
fi

chmod +x "$HOOK_FILE"
echo "✓ Installed hook to $HOOK_FILE"

# Create project hooks.json if in a project directory
if [ -d ".git" ] || [ -f "package.json" ]; then
  mkdir -p .claude

  if [ -f "$HOOKS_JSON" ]; then
    echo "⚠ $HOOKS_JSON already exists - please add SPEAR manually:"
    echo ""
    echo '  "PostToolUse": [{'
    echo '    "matcher": "*",'
    echo '    "hooks": [{'
    echo '      "type": "command",'
    echo "      \"command\": \"node $HOOK_FILE\","
    echo '      "timeout": 2000'
    echo '    }]'
    echo '  }]'
  else
    cat > "$HOOKS_JSON" << EOF
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node $HOOK_FILE",
            "timeout": 2000
          }
        ]
      }
    ]
  }
}
EOF
    echo "✓ Created $HOOKS_JSON"
  fi
fi

echo ""
echo "Installation complete!"
echo ""
echo "Verify with: claude /hooks"
echo ""
