# Deployment Quick Reference

For the full security analysis and architecture documentation, see the [main README](../../README.md).

This document provides a condensed deployment checklist.

## Pre-Flight Checklist

- [ ] Raspberry Pi 4 (4GB+) or Pi 5
- [ ] Raspberry Pi OS 64-bit installed
- [ ] SSH access configured
- [ ] Adequate cooling (heatsink + fan recommended)
- [ ] Stable internet connection

## Deployment Steps

### 1. System Preparation
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Run Setup Script
```bash
./scripts/setup-raspberry-pi.sh
```

This installs:
- Rust toolchain
- PostgreSQL 15/16 with pgvector
- IronClaw (compiled from source)
- Configuration files

### 3. Create Telegram Bot
1. Open Telegram, message [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Choose a name and username
4. Save the token

### 4. Configure IronClaw
```bash
# Add bot token
~/ironclaw/target/release/ironclaw secrets add TELEGRAM_BOT_TOKEN

# Run setup wizard
~/ironclaw/target/release/ironclaw setup
```

### 5. Verify Security
```bash
./tests/security-verification.sh
```

All tests should pass.

### 6. Start Agent
```bash
# Interactive mode
~/ironclaw/target/release/ironclaw

# Or as service
sudo systemctl enable ironclaw
sudo systemctl start ironclaw
```

## File Locations

| File | Location |
|------|----------|
| Configuration | `~/.ironclaw/settings.toml` |
| System prompt | `~/.ironclaw/system_prompt.md` |
| Audit logs | `/var/log/ironclaw/audit.log` |
| Notes | `~/ironclaw-notes/` |
| Binary | `~/ironclaw/target/release/ironclaw` |
| Service | `/etc/systemd/system/ironclaw.service` |

## Common Commands

```bash
# Check service status
systemctl status ironclaw

# View logs
journalctl -u ironclaw -f

# View audit log
tail -f /var/log/ironclaw/audit.log

# Restart after config change
sudo systemctl restart ironclaw

# Monitor network
sudo ./scripts/monitor-network.sh 30
```

## Troubleshooting

### Service won't start
```bash
journalctl -u ironclaw -n 100
# Check for missing dependencies or config errors
```

### Database connection failed
```bash
systemctl status postgresql
sudo -u postgres psql -c "SELECT 1;"
```

### Bot not receiving messages
```bash
# Test token directly
curl "https://api.telegram.org/bot<TOKEN>/getMe"
```

## Security Verification Commands

```bash
# Verify only Telegram traffic
sudo tcpdump -i any -n 'not host api.telegram.org and not localhost' -c 10

# Check for injection attempts
grep -i "injection\|blocked" /var/log/ironclaw/audit.log

# Verify config permissions
stat -c %a ~/.ironclaw/settings.toml  # Should be 600
```

## Updating

```bash
cd ~/ironclaw
git pull
cargo build --release
sudo systemctl restart ironclaw
```

Always run security verification after updates.
