#
# Copyright Cray Inc. All Rights Reserved
#
%if %{undefined %namespace}
%define namespace cray
%endif

%define intranamespace_name dvs
%undefine release_prefix
%define release_suffix %{release_extra}
%define inst_path %{_namespace_prefix}/%{namespace}-%{intranamespace_name}-kmp
%define mani_path /etc/opt/cray/release/manifests
%define libmod lib/modules
%define mod_list dvsipc dvsof dvsproc dvspn dvsutil
%define up_alt /usr/sbin/update-alternatives
%define inss /usr/sbin/insserv
%if 0%{?suse_version:1} && 0%{?suse_version} < 1200
%define alt_files -f cray-dvs-kernel-package
%else
%define alt_files %{nil}
%endif

%if %{with shasta}
%define dvs_dracut		scripts/80cray-dvs
%define ansible_dvs_dracut	scripts/80cray-ansible-dvs
%define ulib_dracut		/usr/lib/dracut
%define dracut_modules		%{ulib_dracut}/modules.d
%endif

# Choose whether to use ansible in scripts
%if 0%{?suse_version} >= 1200
%define _enable_ansible --enable-ansible
%else
%define _enable_ansible --disable-ansible
%endif

%ifarch k1om
%define _without_service --without-service
%endif
%if %{with shasta_premium}
%define _without_service --without-service
%endif

%if %{without service}
%define _without_docs --without-docs
%endif

%bcond_with clevm

%if 0%{?clevm}
%define with_clevm 1
%endif

%if (%{without shasta} && %{without ari} && %{without gni} && %{without ss}) || 0%{with clevm}
%define _without_docs --without-docs
%define _without_rca --without-rca
%define _without_hss --without-hss
%endif

%if %{with shasta}
%define _without_rca --without-rca
%define _without_hss --without-hss
%endif

# Default off (enable: obs build --with pedantic_build ...)
%bcond_with pedantic_build

# Default on (disable: obs build --without rca ...)
%bcond_without rca
%bcond_without hss
%bcond_without docs
%bcond_without service
%bcond_without katlas

%if 0%{?sles_version} == 10
BuildRequires: cray-rpm
%endif

%if 0%{with ss}
BuildRequires: cray-libportals-devel
%endif

%if 0%{with rca}
BuildRequires: cray-krca-devel
BuildRequires: cray-librca-devel
%endif

%if 0%{with hss}
%ifarch k1om
BuildRequires: cray-hss-knc-devel
%else
BuildRequires: lsb-cray-hss-devel
%endif
%endif

%if %{defined lustre_build_stock}
BuildRequires: lustre-client-devel
%else
%if 0%{?suse_version} < 1200 || 0%{with clevm}
BuildRequires: cray-lnet-%{lnet_version}-devel
%else
%if %{with shasta}
BuildRequires: cray-lustre-client-lnet-headers
%if %{with shasta_premium}
BuildRequires: cray-lustre-client-cray_shasta_c-lnet-devel
%endif
%if %{with shasta_base}
BuildRequires: cray-lustre-client-default-lnet-devel
%endif
%else
BuildRequires: cray-lustre-cray_ari_c-%{lnet_version}-devel
BuildRequires: cray-lustre-cray_ari_s-%{lnet_version}-devel
%endif
%endif
%endif

%if 0%{with katlas}
BuildRequires: cray-katlas-devel
%endif
%if %{with docs}
BuildRequires: cray-xml2roff
%endif
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: pkgconfig
BuildRequires: module-init-tools
BuildRequires: update-alternatives
%if %{without athena}
BuildRequires: insserv
%endif
BuildRequires: libtool
BuildConflicts: post-build-checks
BuildConflicts: rpmlint-Factory
Group: System/Filesystems
License: Cray Software License Agreement
Name: %{namespace}-%{intranamespace_name}
Vendor: Cray Inc.
Version: %{lnet_version}_%{_tag}
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Release: %{release}
Source: %{name}-%{_tag}.tar.bz2
Source2: preamble
Summary: Data Virtualization Service

%package test
Summary: DVS test code
Group: Development/Test

%package devel
Summary: DVS header files
Group: Development/Libraries
Requires: pkgconfig
Provides: cray-dvs-devel

%package compute
Group: System/Filesystems
Requires: %{name}-kmp
Requires: update-alternatives
%if 0%{?suse_version} >= 1200
Requires: insserv-compat
%endif
Summary: DVS for compute nodes

%if %{with service}
%package service
Group: System/Filesystems
%if %{with docs}
Requires: cray-man
%endif
Requires: %{name}-kmp
Requires: update-alternatives
Summary: DVS for service nodes
%endif

%if %{with shasta}
%kernel_module_package %{alt_files} -p %{SOURCE2} -x cray_shasta_s
%if %{with shasta_premium}
%define krel %(make -s -C /usr/src/linux-obj/x86_64/cray_shasta_c kernelrelease)
%endif
%if %{with shasta_base}
%define krel %(make -s -C /usr/src/linux-obj/x86_64/default kernelrelease)
%endif
%endif

%if %{with ss}
%cray_kernel_module_package -x cray_ss_c cray_ss_s
%define krel %(make -s -C /usr/src/linux-obj/x86_64/cray_ss_s kernelrelease)
%endif

%if %{with gni}
%cray_kernel_module_package %{alt_files} -x cray_gem_c cray_gem_s
%define krel %(make -s -C /usr/src/linux-obj/x86_64/cray_gem_s kernelrelease)
%endif

%if %{with ari}
%ifarch k1om
%cray_kernel_module_package %{alt_files} -x cray_ari_m
%define krel %(make -s -C /usr/src/linux-obj/k1om/cray_ari_m kernelrelease)
%else
%if %{with athena}
%kernel_module_package %{alt_files}
%else
%cray_kernel_module_package %{alt_files} -p %{SOURCE2} -x cray_ari_c cray_ari_s
%define krel %(make -s -C /usr/src/linux-obj/x86_64/cray_ari_c kernelrelease)
%endif
%endif
%endif

%if 0%{with clevm}
%suse_kernel_module_package -p %{SOURCE2}
%endif

%define kernel_release %(echo %krel | cut -d - -f 1-2 --output-delimiter=_)
%define KERNELRELEASE %(echo %krel | cut -d - -f 1-2)
%define release_version %{version}_%{kernel_release}-%{release}

%package KMP
Summary: DVS kernel modules
Group: System/Kernel

%description KMP
Data Virtualization Service kernel modules.

%description
Data Virtualization Service for both compute and service nodes.

%description test
Data Virtualization Service regression tests

%description devel
Data Virtualization Service header files

%description compute
Data Virtualization Service for compute nodes.

%if %{with service}
%description service
Data Virtualization Service for service nodes.
%endif

%prep
%incremental_setup -n %{name}-%{_tag}

%define lnet_id %(echo %lnet_version | cut -c1-3 | sed 's/\\.//')

%if "%{lnet_id}" == "mas"
%define lnet_maj 3
%define lnet_min 0
%else
%define lnet_maj %(echo "%{lnet_version}" | awk -F. '{print $1}')
%define lnet_min %(echo "%{lnet_version}" | awk -F. '{print $2}')
%endif

%build
%if %{with shasta}
%if %{with shasta_premium}
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib64/pkgconfig/cray_shasta_c
%endif
%else
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib64/pkgconfig/cray_ari_c:/usr/lib64/pkgconfig/cray_ari_s
%endif
# Fix for automake 1.13 and above.  Integrate directly into configure.in once
# the oldest version of automake used at Cray exceeds v1.11
%ifarch k1om
%__sed -i -e 's/AM_CONFIG_HEADER/AC_CONFIG_HEADER/' configure.ac
autoreconf -i
%endif

%CRAYconfigure -- --with-default-prefix=%{_default_prefix} --with-module=%{_release_modulefile} --with-subversion-revision=%{svnrev} --with-lnet-version=%{lnet_version} %{?_without_rca} %{?_without_hss} %{?_without_docs} %{?_without_katlas} %{_enable_ansible}

# copy source for KMP only after configure
# copy all of source so include headers are in correct relative position
set -- *
%{__mkdir} source
%{__cp} -r "$@" source/
%{__mkdir} obj

%{__make}

flags=""
flags="$flags %{?_with_pedantic_build:-Werror}"
flags="$flags -DLNETVER=\\\"%{lnet_id}\\\""
flags="$flags -DSVNREV=\\\"%{svnrev}\\\""
%if %{with athena}
flags="$flags -DCRAY_ATHENA=1"
%endif

%if 0%{with clevm}
export WHITEBOX=1
%else
%if %{with shasta}
export SHASTA=1
%else
flags="$flags -DUSE_RCA=1"
krca_flags=$(pkg-config cray-krca --cflags)
krca_sym_dir=$(pkg-config --variable=symversdir cray-krca)
%endif
%endif

export GPL_LICENSE=1

export SVNREV=%{svnrev}
export LNETVER=%{lnet_id}

%if %{without shasta}
flags="$flags $krca_flags"
%endif
lnet_flags=$(pkg-config --cflags cray-lnet)
lnet_sym_dir=$(pkg-config --variable=symversdir cray-lnet)
lnet_inc_dir=$(pkg-config --variable=includedir cray-lnet)
%if 0%{with katlas}
katlas_sym_dir=$(pkg-config --variable=symversdir cray-katlas)
%endif

export KCPPFLAGS=${flags}
%if %{without shasta}
export IPC_FLAGS=${krca_flags}
%endif
# LNet's pkg-config file did not always have the include directory in its cflags
export LNET_FLAGS="${lnet_flags} -I${lnet_inc_dir}"

for flavor in %flavors_to_build; do
    %if %{without shasta}
    syms="${krca_sym_dir}/${flavor}/Module.symvers"
    %endif

    if [ -f "${lnet_inc_dir}/%{_arch}/${flavor}/config.h" ]; then
        export LNET_FLAGS="-include ${lnet_inc_dir}/%{_arch}/${flavor}/config.h ${lnet_flags}"
    fi
    if [ -f "${lnet_sym_dir}/%{_arch}/${flavor}/Module.symvers" ]; then
        syms="${syms} ${lnet_sym_dir}/%{_arch}/${flavor}/Module.symvers"
    else
        for sym in $([ ! -d /opt/cray ] || find /opt/cray  -path "/opt/cray/cray-lustre-${flavor}*/Module.symvers"); do
            syms="${sym} ${syms}"
        done
    fi
    %if 0%{with katlas} && "${flavor}" == "service"
	export CONFIG_KATLAS=1
        syms="${syms} ${katlas_sym_dir}/${flavor}/Module.symvers"
    %endif
    export KBUILD_EXTRA_SYMBOLS=${syms}
    rm -rf obj/$flavor
    cp -r source obj/$flavor
    %{__make} %_smp_mflags -C %{kernel_source $flavor} M=$PWD/obj/$flavor/kernel WITH_PREFIX=%{_sbindir} modules
done

%install
%make_install

# for KMP
%if 0%{?suse_version:1} && 0%{?suse_version} < 1200
export INSTALL_MOD_PATH=${RPM_BUILD_ROOT}/%{inst_path}/%{release_version}
export INSTALL_MOD_DIR=updates/dvskmp
%else
export INSTALL_MOD_PATH=${RPM_BUILD_ROOT}
%endif

for flavor in %{flavors_to_build}
do
	%{__make} -C %{kernel_source $flavor} modules_install M=$PWD/obj/$flavor/kernel
	%{__install} -D ${PWD}/obj/${flavor}/kernel/Module.symvers ${RPM_BUILD_ROOT}/%{_datadir}/symvers/${flavor}/Module.symvers
done

%if %{without service}
%__rm %{buildroot}/%{_sysconfdir}/init.d/dvs
%endif

%if %{with shasta}
%{__mkdir_p}		%{buildroot}%{dracut_modules}
cp -r %{dvs_dracut}	%{buildroot}%{dracut_modules}
cp -r %{ansible_dvs_dracut}	%{buildroot}%{dracut_modules}
%endif

%files compute
%defattr (-,root,root,755)
%prefixdirs
%switch_files
%dir %{_sysconfdir}/init.d
%dir %{_base_sysconfdir}/modprobe.d
%attr(0644,root,root) %{_sysconfdir}/init.d/functions
%{_sysconfdir}/init.d/dvs.cnl
%{_sbindir}/dvs_thread_generator
%config %attr(0644,root,root) %{_base_sysconfdir}/modprobe.d/dvs.conf
%config %attr(0644,root,root) %{_base_sysconfdir}/modprobe.d/dvs-private.conf
%if %{with shasta}
%defattr(-,root,root)
%{dracut_modules}
%defattr(0755, root, root)
%dir %{dracut_modules}/*
%endif

%if %{with service}
%files service
%defattr (-,root,root,755)
%prefixdirs
%switch_files
%if %{with docs}
%{_mandir}
%endif
%dir %{_sysconfdir}/init.d
%dir %{_base_sysconfdir}/modprobe.d
%attr(0644,root,root) %{_sysconfdir}/init.d/functions
%{_sysconfdir}/init.d/dvs
%{_sbindir}/dvs_thread_generator
%config %attr(0644,root,root) %{_base_sysconfdir}/modprobe.d/dvs.conf
%config %attr(0644,root,root) %{_base_sysconfdir}/modprobe.d/dvs-private.conf
%if %{with shasta}
%defattr(-,root,root)
%{dracut_modules}
%defattr(0755, root, root)
%dir %{dracut_modules}/*
%endif
%endif

%files test
%defattr (-,root,root,755)
%{_sbindir}/test_common.sh
%{_sbindir}/test_request_log.sh
%{_sbindir}/regression_test.py
%{_sbindir}/test_common
%{_sbindir}/test_stats
%{_sbindir}/test_rdwr_mmap
%{_sbindir}/test_read_file
%{_sbindir}/test_read_mmap
%{_sbindir}/test_spinlock_perf
%{_sbindir}/test_write_file
%{_sbindir}/test_write_mmap
%{_sbindir}/test_write_random
%{_sbindir}/ioperf
%{_sbindir}/xattr_stress

%files devel
%defattr (-,root,root,755)
%switch_files
%{_includedir}/dvs_ioctl.h
%{_includedir}/ssi_util_init.h
%{_includedir}/ipc_api.h
%{_includedir}/usifunc.h
%{_includedir}/dvsproc_node.h
%dir %{_datadir}/symvers/*
%attr (644,root,root) %{_datadir}/symvers/*/Module.symvers
%pkg_config_files -n cray-dvs

%clean
%clean_build_root

%post compute
if ! grep '^include /etc/modprobe.d$' /etc/modprobe.conf >/dev/null 2>/dev/null
then
    echo 'include /etc/modprobe.d' >>/etc/modprobe.conf
fi

%if 0%{?suse_version} < 1200
for flavor in %{flavors_to_build}
do
    [ -d %{inst_path}/%{release_version}/%{libmod}/%{KERNELRELEASE}-${flavor} ] && break
done

for mod in %{mod_list}
do
    if [ -d /%{libmod}/%{KERNELRELEASE}-${flavor} ]
    then
        %{__mv}  %{inst_path}/%{release_version}/%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp/${mod} /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/
    fi
done
%endif

%install_switch
%{__ln_s} -f dvs.cnl %{_sysconfdir}/init.d/dvs
%link_service dvs

%if %{with service}
%post service

%if 0%{?suse_version} >= 1200
#### SLES 12 / NO SHARED ROOT INSTALL ####

if ! grep '^include /etc/modprobe.d$' /etc/modprobe.conf >/dev/null 2>/dev/null
then
    echo 'include /etc/modprobe.d' >>/etc/modprobe.conf
fi
%else
%if !%{with clevm}
#### SLES 11 / SHARED ROOT INSTALL ####
for flavor in %{flavors_to_build}
do
    [ -d %{inst_path}/%{release_version}/%{libmod}/%{KERNELRELEASE}-${flavor} ] && break
done

if [ -d /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvsipc ]
then
    %{__mkdir} -p %{inst_path}/save/%{KERNELRELEASE}-${flavor}
    %{__mv} /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvs* %{inst_path}/save/%{KERNELRELEASE}-${flavor}/
fi

%{up_alt} --install %{inst_path}/default cray-dvs-kmp-${flavor} %{inst_path}/%{release_version} %{release_priority}
%{up_alt} --set cray-dvs-kmp-${flavor} %{inst_path}/%{release_version}

%{inss} --install %{inst_path}/default cray-dvs-kmp-${flavor} %{inst_path}/%{release_version} %{release_priority}
%{inss} --set cray-dvs-kmp-${flavor} %{inst_path}/%{release_version}

# create a link to lib modules
%{__ln_s} -f -n %{inst_path}/default/%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp

#run depmod after lib/modules links are created so proper dvs kos are found
if [ -e /boot/System.map-%{KERNELRELEASE}-${flavor} ]; then
	/sbin/depmod -a -F /boot/System.map-%{KERNELRELEASE}-${flavor} %{KERNELRELEASE}-${flavor}
fi
%endif   # undefined clevm
%endif   # SLES 11

%install_switch
%if %{with docs}
for path in `find %{_mandir} -type f`
do
    file_name=`basename $path`
    category=${file_name##*.}

    if [ -e "%{_namespace_mandir}/man${category}" ]
    then
        %{__ln_s} -f %{_default_mandir}/man${category}/${file_name} %{_namespace_mandir}/man${category}/${file_name}
    fi
done
if [ -e "%{_namespace_mandir}/whatis" ]
then
    %{__cat} %{_namespace_mandir}/whatis %{_default_mandir}/whatis | sort -uf -o %{_namespace_mandir}/whatis
else
    %{__cp} %{_default_mandir}/whatis %{_namespace_mandir}/whatis
fi
%endif
%link_service dvs

%endif

%post devel
%install_switch
%link_pkg_config -n cray-dvs

%preun compute
%remove_service
if [ -L "%{_sysconfdir}/init.d/dvs" ]
then
    %{__rm} %{_sysconfdir}/init.d/dvs
fi
%remove_switch

%if 0%{?suse_version} < 1200
for flavor in %{flavors_to_build}
do
    [ -d /%{libmod}/%{KERNELRELEASE}-${flavor} ] && break
done

for mod in %{mod_list}
do
    [ -d /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/${mod} ] && %{__rm} -rf /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/${mod}
done
%endif

%if %{with service}
%preun service

%if 0%{?suse_version} >= 1200
#### SLES 12 / NO SHARED ROOT UNINSTALL ####

%remove_service
if [ -L "%{_sysconfdir}/init.d/dvs" ]
then
    %{__rm} %{_sysconfdir}/init.d/dvs
fi
%remove_switch

%else
#### SLES 11 / SHARED ROOT UNINSTALL ####

%stop_on_removal dvs
%if %{with docs}
# if uninstall and not updating
if [ "$1" = "0" ]
then
    for path in `find %{_mandir} -type f`
    do
        file_name=`basename $path`
        category=${file_name##*.}

        if [ -L "%{_namespace_mandir}/man${category}/${file_name}" ]
        then
            %{__rm} %{_namespace_mandir}/man${category}/${file_name}
            man_name=${file_name##*/}
            %{__perl} -n -i -e "s/^${man_name%.*}\s*\(${category}\w*\).*\n?//;print" %{_namespace_mandir}/whatis
        fi
    done
fi
%endif
%remove_switch

%endif
%endif

%preun devel
%remove_pkg_config -n cray-dvs
%remove_switch

%if %{with service}
%postun service

%if 0%{?suse_version} >= 1200
#### SLES 12 / NO SHARED ROOT UNINSTALL ####

%remove_service dvs
%insserv_cleanup

%else
#### SLES 11 / SHARED ROOT UNINSTALL ####
%if !%{with clevm}
. /etc/opt/cray/release/xtrelease
for flavor in %{flavors_to_build}; do
    grep -q cray-dvs-kmp-${flavor} %{mani_path}/${DEFAULT}
    [ $? -ne 0 ] && continue
    [ -d /%{libmod}/%{KERNELRELEASE}-${flavor} ] && break
done
cur_vers=$(grep cray-dvs-kmp-${flavor} %{mani_path}/${DEFAULT} | awk -F'|' '{ print $2 }')

%{up_alt} --remove cray-dvs-kmp-${flavor} %{inst_path}/%{release_version}
%{inss} --remove cray-dvs-kmp-${flavor} %{inst_path}/%{release_version}

if [ -d %{inst_path}/${cur_vers}/%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp/dvsipc -a "${cur_vers}" != "%{release_version}" ]; then
    pkg_path="`%{up_alt} --list cray-dvs-kmp-${flavor} | grep ${cur_vers}`"
    if [ "${pkg_path}" != "" ]; then
	%{up_alt} --set cray-dvs-kmp-${flavor} ${pkg_path}
    fi
    pkg_path="`%{inss} --list cray-dvs-kmp-${flavor} | grep ${cur_vers}`"
    if [ "${pkg_path}" != "" ]; then
        %{inss} --set cray-dvs-kmp-${flavor} ${pkg_path}
    fi

else if [ -d %{inst_path}/save/%{KERNELRELEASE}-${flavor}/dvsipc ]; then
    %{__mv} %{inst_path}/save/%{KERNELRELEASE}-${flavor}/dvs* /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/
fi

[ ! -d %{inst_path}/save/%{KERNELRELEASE}-${flavor}/dvsipc ] && %{__rm} -rf %{inst_path}/save

# Remove link related to release_version:
pkg_path="`%{up_alt} --list cray-dvs-kmp-${flavor} | grep %{kernel_release}`"
if [ "${pkg_path}" = "" ]; then
    %{__rm} -f /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp
fi

# Remove link related to release_version:
pkg_path="`%{inss} --list cray-dvs-kmp-${flavor} | grep %{kernel_release}`"
if [ "${pkg_path}" = "" ]; then
    %{__rm} -f /%{libmod}/%{KERNELRELEASE}-${flavor}/updates/dvskmp
fi

%endif

%remove_service dvs
%insserv_cleanup
%restart_on_update dvs
%endif
%endif

%postun compute
%remove_service dvs
%insserv_cleanup
