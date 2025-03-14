
# rpmbuild -ba mtr085.spec

%define gtag 97af563
%define gver .%(echo "$(git rev-list --count %{gtag}..HEAD)_$(git rev-parse --short HEAD)")

Name:       mtr085
Version:    0.85%{gver}
Release:    1
Summary:    Full screen ncurses traceroute tool
License:    GPL-2.0
Group:      Productivity/Networking/Other
URL:        https://github.com/yvs2014/%{name}

Requires: ncurses
BuildRequires: meson, git, sed, pkgconf, gettext-runtime, ncurses-devel, libcap-devel
BuildRequires: (gcc or clang)
%if 0%{?fedora}
Requires: libcap
%else
Requires: libcap2
BuildRequires: libcap-progs
%endif
Conflicts: mtr, mtr-gtk

%description
mtr combines the functionality of the traceroute and ping programs in a single network diagnostic tool.
Built from https://github.com/yvs2014/mtr085 fork with whois info, unicode, etc.
Main project's location is https://github.com/traviscross/mtr

%define binname mtr
%define prefix /usr

%prep
%autosetup

%build
%meson
%meson_build

%install
%meson_install
%find_lang %{name}

%post
setcap cap_net_raw+p %{_bindir}/%{binname}

%files -f %{name}.lang
%defattr(-,root,root,-)
%{_bindir}/%{binname}
%{_mandir}/man8/%{binname}.8*

%changelog
# autofill

