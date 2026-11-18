#!/bin/bash
#
# SPEAR Hook Installer for Claude Code
#
# Usage: curl -fsSL https://raw.githubusercontent.com/sunnypatneedi/spear/main/packages/hook/install.sh | bash
#

set -e

REPO_RAW="https://raw.githubusercontent.com/sunnypatneedi/spear/main"
HOOK_DIR="$HOME/.claude/hooks"
HOOK_FILE="$HOOK_DIR/spear-hook.mjs"
# Claude Code reads hooks from settings files, not from a standalone hooks.json.
SETTINGS_JSON=".claude/settings.json"
HOOK_COMMAND="node ~/.claude/hooks/spear-hook.mjs"

echo "Installing SPEAR Hook for Claude Code..."

# Create hooks directory
mkdir -p "$HOOK_DIR"

# Download hook script
if command -v curl &> /dev/null; then
  curl -fsSL -o "$HOOK_FILE" "$REPO_RAW/packages/hook/spear-hook.mjs"
elif command -v wget &> /dev/null; then
  wget -q -O "$HOOK_FILE" "$REPO_RAW/packages/hook/spear-hook.mjs"
else
  echo "Error: curl or wget required"
  exit 1
fi

chmod +x "$HOOK_FILE"
echo "✓ Installed hook to $HOOK_FILE"

print_snippet() {
  cat << EOF
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "$HOOK_COMMAND", "timeout": 2000 }
        ]
      }
    ]
  }
EOF
}

# Register the hook in project settings if in a project directory
if [ -d ".git" ] || [ -f "package.json" ]; then
  mkdir -p .claude

  if [ -f "$SETTINGS_JSON" ]; then
    echo "⚠ $SETTINGS_JSON already exists. Add SPEAR to it manually (merge with any existing \"hooks\"):"
    echo ""
    print_snippet
  else
    {
      echo "{"
      print_snippet
      echo "}"
    } > "$SETTINGS_JSON"
    echo "✓ Created $SETTINGS_JSON"
  fi
else
  echo "Not in a project directory. To enable SPEAR for all projects, add this to ~/.claude/settings.json:"
  echo ""
  print_snippet
fi

echo ""
echo "Installation complete!"
echo ""
echo "Verify with: claude /hooks"
echo ""
