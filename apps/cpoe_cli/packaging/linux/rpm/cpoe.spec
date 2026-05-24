# RPM spec file for cpop
# Cryptographic Authorship Witnessing - Kinetic Proof of Provenance

%global debug_package %{nil}
%global __strip /bin/true

Name:           cpop
Version:        1.0.0
Release:        1%{?dist}
Summary:        Cryptographic authorship witnessing daemon

License:        Proprietary
URL:            https://github.com/writerslogic/cpop
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo >= 1.75
BuildRequires:  git
BuildRequires:  systemd-rpm-macros

Requires:       systemd

%description
CPOP provides cryptographic authorship witnessing through kinetic
proof of provenance. It captures keystroke dynamics and timing patterns
to create unforgeable evidence of human authorship.

Features:
- Merkle Mountain Range (MMR) append-only log
- Ed25519 digital signatures
- Privacy-preserving keystroke biometrics
- Multi-anchor timestamping (blockchain, Keybase, etc.)
- Forensic analysis toolkit

%package -n cpop-ibus
Summary:        IBus integration for cpop
Requires:       %{name} = %{version}-%{release}
Requires:       ibus >= 1.5

%description -n cpop-ibus
IBus input method engine for cpop that captures keystroke dynamics
through the Linux input method framework.

This package provides system-wide keystroke witnessing through IBus
without requiring elevated privileges.

%prep
%autosetup

%build
cargo build --release --package cpop_cli

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/cpop
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_userunitdir}
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_sharedstatedir}/cpop
install -d %{buildroot}%{_localstatedir}/log/cpop
install -d %{buildroot}%{_datadir}/doc/%{name}
install -d %{buildroot}%{_datadir}/ibus/component

# Install binaries
install -p -m 755 target/release/cpop %{buildroot}%{_bindir}/cpop
install -p -m 755 target/release/cpop-native-messaging-host %{buildroot}%{_bindir}/cpop-native-messaging-host

# Install man pages
install -p -m 644 docs/man/cpoe.1 %{buildroot}%{_mandir}/man1/cpoe.1

# Install systemd units
install -p -m 644 apps/cpop_cli/packaging/linux/systemd/cpop.service %{buildroot}%{_unitdir}/cpop.service
install -p -m 644 apps/cpop_cli/packaging/linux/systemd/cpop.socket %{buildroot}%{_unitdir}/cpop.socket
install -p -m 644 apps/cpop_cli/packaging/linux/systemd/cpop-user.service %{buildroot}%{_userunitdir}/cpop.service
install -p -m 644 apps/cpop_cli/packaging/linux/systemd/cpop-ibus.service %{buildroot}%{_userunitdir}/cpop-ibus.service

# Install config
install -p -m 640 configs/config.example.toml %{buildroot}%{_sysconfdir}/cpop/config.toml.default

# Install environment file
cat > %{buildroot}%{_sysconfdir}/cpop/environment << 'EOF'
# Environment variables for cpop
# CPOP_LOG_LEVEL=info
# CPOP_DATA_DIR=/var/lib/cpop
# CPOP_CONFIG=/etc/cpop/config.toml
EOF

# Install documentation
install -p -m 644 LICENSE %{buildroot}%{_datadir}/doc/%{name}/LICENSE
install -p -m 644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

# Install IBus component (if available)
if [ -f apps/cpop_cli/packaging/linux/systemd/cpop-ibus.xml ]; then
    sed 's|/usr/local/bin|/usr/bin|g' apps/cpop_cli/packaging/linux/systemd/cpop-ibus.xml > %{buildroot}%{_datadir}/ibus/component/cpop.xml
    chmod 644 %{buildroot}%{_datadir}/ibus/component/cpop.xml
fi

%pre
# Create cpop user and group
getent group cpop >/dev/null || groupadd -r cpop
getent passwd cpop >/dev/null || \
    useradd -r -g cpop -d %{_sharedstatedir}/cpop -s /sbin/nologin \
    -c "CPOP Daemon" cpop
exit 0

%post
%systemd_post cpop.service cpop.socket

# Create default config if it doesn't exist
if [ ! -f %{_sysconfdir}/cpop/config.toml ]; then
    cp %{_sysconfdir}/cpop/config.toml.default %{_sysconfdir}/cpop/config.toml
    chmod 640 %{_sysconfdir}/cpop/config.toml
    chown root:cpop %{_sysconfdir}/cpop/config.toml
fi

# Set ownership on data directories
chown -R cpop:cpop %{_sharedstatedir}/cpop
chown -R cpop:cpop %{_localstatedir}/log/cpop

%preun
%systemd_preun cpop.service cpop.socket

%postun
%systemd_postun_with_restart cpop.service cpop.socket

%post -n cpop-ibus
# Restart IBus to pick up the new component
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%postun -n cpop-ibus
# Restart IBus after removal
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/cpop
%{_bindir}/cpop-native-messaging-host
%{_mandir}/man1/cpoe.1*
%{_unitdir}/cpop.service
%{_unitdir}/cpop.socket
%{_userunitdir}/cpop.service
%dir %{_sysconfdir}/cpop
%config(noreplace) %attr(640,root,cpop) %{_sysconfdir}/cpop/config.toml.default
%config(noreplace) %attr(640,root,cpop) %{_sysconfdir}/cpop/environment
%dir %attr(750,cpop,cpop) %{_sharedstatedir}/cpop
%dir %attr(750,cpop,cpop) %{_localstatedir}/log/cpop
%{_datadir}/doc/%{name}/

%files -n cpop-ibus
%{_bindir}/cpop-ibus
%{_userunitdir}/cpop-ibus.service
%{_datadir}/ibus/component/cpop.xml

%changelog
* Mon Jan 27 2025 David Condrey <david@condrey.dev> - 1.0.0-1
- Initial release
- Cryptographic authorship witnessing daemon
- witnessctl control utility
- IBus input method engine integration
- Systemd service files for system and user services
