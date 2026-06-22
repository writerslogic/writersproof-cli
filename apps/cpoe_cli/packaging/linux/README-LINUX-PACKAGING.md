# Linux Packaging for CPoE

This directory contains all the packaging infrastructure for building and distributing CPoE on Linux systems.

## Package Formats

### 1. Debian Package (.deb)

For Debian, Ubuntu, Linux Mint, and derivatives.

**Location:** `platforms/linux/debian/`

**Contents:**
- `control` - Package metadata and dependencies
- `rules` - Build rules (debhelper)
- `changelog` - Version history
- `copyright` - License information
- `conffiles` - Configuration files to preserve on upgrade
- `postinst` - Post-installation script
- `prerm` - Pre-removal script
- `postrm` - Post-removal script

**Building:**
```bash
# Using the build script
./platforms/linux/scripts/build-deb.sh [version]

# Or manually
cd /path/to/writerslogic
dpkg-buildpackage -us -uc -b
```

**Installing:**
```bash
sudo apt install ./cpoe_1.0.0-1_amd64.deb

# Or with dependencies
sudo dpkg -i cpoe_1.0.0-1_amd64.deb
sudo apt-get -f install
```

### 2. RPM Package (.rpm)

For Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux, openSUSE, and derivatives.

**Location:** `platforms/linux/rpm/`

**Contents:**
- `cpoe.spec` - Full RPM spec file

**Building:**
```bash
# Using the build script
./platforms/linux/scripts/build-rpm.sh [version]

# Or manually
rpmbuild -ba platforms/linux/rpm/cpoe.spec
```

**Installing:**
```bash
# Fedora/RHEL
sudo dnf install ./cpoe-1.0.0-1.fc39.x86_64.rpm

# openSUSE
sudo zypper install ./cpoe-1.0.0-1.x86_64.rpm
```

### 3. AppImage

Portable Linux application format that works on most distributions.

**Location:** `platforms/linux/appimage/`

**Contents:**
- `AppRun` - Entry point script
- `cpoe.desktop` - Desktop entry file
- `cpoe.appdata.xml` - AppStream metadata
- `linuxdeploy.yaml` - linuxdeploy configuration
- `icons/` - Application icons

**Building:**
```bash
./platforms/linux/scripts/build-appimage.sh [version] [arch]

# Example
./platforms/linux/scripts/build-appimage.sh 1.0.0 x86_64
```

**Running:**
```bash
chmod +x cpoe-1.0.0-x86_64.AppImage
./cpoe-1.0.0-x86_64.AppImage

# With desktop integration
./cpoe-1.0.0-x86_64.AppImage --install
```

## Systemd Integration

**Location:** `platforms/linux/systemd/`

### Service Files

| File | Description |
|------|-------------|
| `cpoe.service` | Main daemon (system-wide) |
| `cpoe-user.service` | User-level service |
| `cpoe.socket` | Socket activation |
| `cpoe-ibus.service` | IBus engine (user service) |
| `cpoe.conf` | tmpfiles.d configuration |
| `environment` | Environment variables |

### System Service

```bash
# Enable and start system-wide service
sudo systemctl enable --now cpoe.service

# Check status
sudo systemctl status cpoe.service

# View logs
sudo journalctl -u cpoe.service -f
```

### User Service

```bash
# Enable user service (no sudo)
systemctl --user enable --now cpoe.service

# Check status
systemctl --user status cpoe.service
```

### Socket Activation

```bash
# Enable socket activation
sudo systemctl enable cpoe.socket
sudo systemctl start cpoe.socket
```

## IBus Integration

The `cpoe-ibus` package provides IBus input method integration.

```bash
# Enable IBus service
systemctl --user enable --now cpoe-ibus.service

# Restart IBus to pick up the new engine
ibus restart

# Or add via GNOME Settings > Keyboard > Input Sources
```

## FHS Compliance

The packages follow the Filesystem Hierarchy Standard:

| Path | Purpose |
|------|---------|
| `/usr/bin/cpoe` | Main daemon binary |
| `/usr/bin/witnessctl` | Control utility |
| `/usr/bin/cpoe-ibus` | IBus engine |
| `/etc/writerslogic/` | Configuration files |
| `/etc/writerslogic/config.toml` | Main configuration |
| `/etc/writerslogic/environment` | Environment variables |
| `/var/lib/writerslogic/` | Data (MMR database) |
| `/var/log/writerslogic/` | Log files |
| `/run/writerslogic/` | Runtime data (socket) |
| `/usr/share/doc/writerslogic/` | Documentation |
| `/usr/share/man/man1/` | Man pages |

## Security Hardening

The systemd service includes comprehensive security hardening:

- `NoNewPrivileges=yes` - Prevent privilege escalation
- `PrivateTmp=yes` - Isolated /tmp
- `ProtectSystem=strict` - Read-only system directories
- `ProtectHome=read-only` - Read-only home directories
- `ProtectKernelTunables=yes` - Block sysctl writes
- `PrivateDevices=yes` - No access to physical devices
- `MemoryDenyWriteExecute=yes` - No W+X memory
- `SystemCallFilter=@system-service` - Restricted syscalls
- `CapabilityBoundingSet=` - No capabilities

## Build Scripts

All build scripts are located in `platforms/linux/scripts/`:

| Script | Purpose |
|--------|---------|
| `build-deb.sh` | Build Debian package |
| `build-rpm.sh` | Build RPM package |
| `build-appimage.sh` | Build AppImage |
| `test-packages.sh` | Test packages in Docker |

### Testing Packages

```bash
# Test all package types
./platforms/linux/scripts/test-packages.sh all

# Test specific type
./platforms/linux/scripts/test-packages.sh deb
./platforms/linux/scripts/test-packages.sh rpm
./platforms/linux/scripts/test-packages.sh appimage
```

## CI/CD Integration

The GitHub Actions workflow `.github/workflows/linux-packages.yml` automatically:

1. Builds Debian packages (Ubuntu 22.04)
2. Builds RPM packages (Fedora 39)
3. Builds AppImages
4. Tests packages in Docker containers
5. Uploads packages to GitHub releases (on tag)

### Triggering Builds

```bash
# Automatic on tag push
git tag v1.0.0
git push origin v1.0.0

# Manual workflow dispatch
gh workflow run linux-packages.yml -f version=1.0.0
```

## Package Repository Setup (Optional)

### APT Repository

For hosting your own Debian repository:

```bash
# Directory structure
repo/
  dists/
    stable/
      main/
        binary-amd64/
        binary-arm64/
  pool/
    main/
      w/
        writerslogic/

# Add to sources
echo "deb [signed-by=/path/to/key.gpg] https://repo.example.com/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/writerslogic.list
```

### YUM/DNF Repository

```bash
# Directory structure
repo/
  fedora/
    39/
      x86_64/
    40/
      x86_64/

# Create repository metadata
createrepo_c /path/to/repo/fedora/39/x86_64/

# Add repo file
cat > /etc/yum.repos.d/writerslogic.repo << EOF
[writerslogic]
name=CPoE Repository
baseurl=https://repo.example.com/rpm/fedora/\$releasever/\$basearch/
enabled=1
gpgcheck=1
gpgkey=https://repo.example.com/rpm/RPM-GPG-KEY-writerslogic
EOF
```

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check for errors
sudo journalctl -u cpoe.service -e

# Verify permissions
ls -la /var/lib/writerslogic/
ls -la /etc/writerslogic/
```

**IBus engine not appearing:**
```bash
# Check component file
cat /usr/share/ibus/component/cpoe.xml

# Restart IBus
ibus restart

# Check IBus logs
journalctl --user -u org.freedesktop.IBus -f
```

**AppImage won't run:**
```bash
# Check FUSE
apt install fuse libfuse2

# Extract and run directly
./cpoe.AppImage --appimage-extract
./squashfs-root/usr/bin/cpoe
```

### Verifying Installation

```bash
# Check binary
cpoe version
witnessctl status

# Check service
systemctl status cpoe.service

# Check socket
ls -la /run/writerslogic/cpoe.sock

# Check logs
tail -f /var/log/writerslogic/writerslogic.log
```

## Contributing

When modifying packaging:

1. Test changes locally with build scripts
2. Run `test-packages.sh` in Docker
3. Update version in relevant files
4. Submit PR with test results

## License

See `/usr/share/doc/writerslogic/LICENSE` for license information.
