
# rpmbuild -ba mtr085.spec

%define gtag 97af563
%define gver %(echo "$(git rev-list --count %{gtag}..HEAD)_$(git rev-parse --short HEAD)")

Name:       mtr085
Version:    0.85.%{gver}
Release:    1
Summary:    Full screen ncurses traceroute tool
License:    GPL-2.0
Group:      Productivity/Networking/Other
URL:        https://github.com/yvs2014/%{name}

Requires: ncurses, libidn2
BuildRequires: make, automake, autoconf, pkgconf, ncurses-devel, libidn2-devel, libcap-devel
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
This version is built from https://github.com/yvs2014/mtr085 fork with IDN support, Unicode histograms, extra IP address info, etc.
Main project's location is https://github.com/traviscross/mtr

%define binname mtr
%define srcdir %{name}
%define prefix /usr
%define bindir %{prefix}/bin
%define mandir %{prefix}/share/man/man8

%prep
rm -rf %{srcdir}
git clone https://github.com/yvs2014/%{name}

%build
cd %{srcdir}
autoreconf -fi
./configure --prefix=%{prefix} --with-libidn
make

%install
cd %{srcdir}
DESTDIR=%{buildroot} make install

%post
setcap cap_net_raw+ep %{bindir}/%{binname}

%files
%defattr(-,root,root,-)
%{bindir}/%{binname}
%{mandir}/%{binname}.8.gz

%changelog

