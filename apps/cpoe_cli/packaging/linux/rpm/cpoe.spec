# RPM spec file for cpoe
# Cryptographic Authorship Witnessing - Kinetic Proof of Provenance

%global debug_package %{nil}
%global __strip /bin/true

Name:           cpoe
Version:        1.0.0
Release:        1%{?dist}
Summary:        Cryptographic authorship witnessing daemon

License:        Proprietary
URL:            https://github.com/writerslogic/writersproof-cli
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo >= 1.75
BuildRequires:  git
BuildRequires:  systemd-rpm-macros

Requires:       systemd

%description
CPOE provides cryptographic authorship witnessing through kinetic
proof of provenance. It captures keystroke dynamics and timing patterns
to create unforgeable evidence of human authorship.

Features:
- Merkle Mountain Range (MMR) append-only log
- Ed25519 digital signatures
- Privacy-preserving keystroke biometrics
- Multi-anchor timestamping (blockchain, Keybase, etc.)
- Forensic analysis toolkit

%prep
%autosetup

%build
cargo build --release --package cpoe_cli

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/cpoe
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_userunitdir}
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_sharedstatedir}/cpoe
install -d %{buildroot}%{_localstatedir}/log/cpoe
install -d %{buildroot}%{_datadir}/doc/%{name}

# Install binaries
install -p -m 755 target/release/writersproof-cli %{buildroot}%{_bindir}/writersproof-cli
install -p -m 755 target/release/writerslogic-native-messaging-host %{buildroot}%{_bindir}/writerslogic-native-messaging-host

# Install man pages
install -p -m 644 docs/man/cpoe.1 %{buildroot}%{_mandir}/man1/writersproof-cli.1

# Install systemd units
install -p -m 644 apps/cpoe_cli/packaging/linux/systemd/cpoe.service %{buildroot}%{_unitdir}/cpoe.service
install -p -m 644 apps/cpoe_cli/packaging/linux/systemd/cpoe.socket %{buildroot}%{_unitdir}/cpoe.socket
install -p -m 644 apps/cpoe_cli/packaging/linux/systemd/cpoe-user.service %{buildroot}%{_userunitdir}/cpoe.service

# Install config
install -p -m 640 configs/config.example.toml %{buildroot}%{_sysconfdir}/cpoe/config.toml.default

# Install environment file
cat > %{buildroot}%{_sysconfdir}/cpoe/environment << 'EOF'
# Environment variables for cpoe
# CPOE_LOG_LEVEL=info
# CPOE_DATA_DIR=/var/lib/cpoe
# CPOE_CONFIG=/etc/cpoe/config.toml
EOF

# Install documentation
install -p -m 644 LICENSE %{buildroot}%{_datadir}/doc/%{name}/LICENSE
install -p -m 644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

%pre
# Create cpoe user and group
getent group cpoe >/dev/null || groupadd -r cpoe
getent passwd cpoe >/dev/null || \
    useradd -r -g cpoe -d %{_sharedstatedir}/cpoe -s /sbin/nologin \
    -c "CPOE Daemon" cpoe
exit 0

%post
%systemd_post cpoe.service cpoe.socket

# Create default config if it doesn't exist
if [ ! -f %{_sysconfdir}/cpoe/config.toml ]; then
    cp %{_sysconfdir}/cpoe/config.toml.default %{_sysconfdir}/cpoe/config.toml
    chmod 640 %{_sysconfdir}/cpoe/config.toml
    chown root:cpoe %{_sysconfdir}/cpoe/config.toml
fi

# Set ownership on data directories
chown -R cpoe:cpoe %{_sharedstatedir}/cpoe
chown -R cpoe:cpoe %{_localstatedir}/log/cpoe

%preun
%systemd_preun cpoe.service cpoe.socket

%postun
%systemd_postun_with_restart cpoe.service cpoe.socket

%files
%license LICENSE
%doc README.md
%{_bindir}/writersproof-cli
%{_bindir}/writerslogic-native-messaging-host
%{_mandir}/man1/writersproof-cli.1*
%{_unitdir}/cpoe.service
%{_unitdir}/cpoe.socket
%{_userunitdir}/cpoe.service
%dir %{_sysconfdir}/cpoe
%config(noreplace) %attr(640,root,cpoe) %{_sysconfdir}/cpoe/config.toml.default
%config(noreplace) %attr(640,root,cpoe) %{_sysconfdir}/cpoe/environment
%dir %attr(750,cpoe,cpoe) %{_sharedstatedir}/cpoe
%dir %attr(750,cpoe,cpoe) %{_localstatedir}/log/cpoe
%{_datadir}/doc/%{name}/

%changelog
* Mon Jan 27 2025 David Condrey <david@condrey.dev> - 1.0.0-1
- Initial release
- Cryptographic authorship witnessing daemon
- witnessctl control utility
- IBus input method engine integration
- Systemd service files for system and user services
