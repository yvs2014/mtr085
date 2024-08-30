
# OBS compat

Name:       mtr085
Version:    inherited
Release:    1
Summary:    Full screen ncurses traceroute tool
License:    GPL-2.0
Group:      Productivity/Networking/Other
URL:        https://github.com/yvs2014/%{name}
Source0:    %{name}-%{version}.tar.gz

Requires: ncurses
BuildRequires: make, automake, autoconf, pkgconf, ncurses-devel, libidn2-devel, libcap-devel
BuildRequires: (gcc or clang)
%if 0%{?fedora}
BuildRequires: glibc-langpack-en
%else
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
%setup -q

%build
autoreconf -fi
./configure --prefix=%{prefix} --with-libidn
make

%install
DESTDIR=%{buildroot} make install

%post
setcap cap_net_raw+ep %{bindir}/%{binname}

%files
%defattr(-,root,root,-)
%{bindir}/%{binname}
%{mandir}/%{binname}.8.gz

%changelog

