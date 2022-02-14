#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Shell script to create store package

set -e

#-------------------- Configuration ---------------------------

currentScript=$(basename $0 | cut -d "." -f 1)                 # carbonio-appserver
currentPackage=$(echo ${currentScript}build | cut -d "-" -f 2) # storebuild

#-------------------- Build Package ---------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

main() {
  echo -e "\tCreate package directories"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/bin
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/conf/templates

  echo -e "\tCopy package files"

  echo -e "\tCopy bin files of /opt/zextras/"

  cp -f ${repoDir}/zm-build/rpmconf/Conf/owasp_policy.xml ${repoDir}/zm-build/${currentPackage}/opt/zextras/conf/owasp_policy.xml
  cp -f ${repoDir}/zm-build/rpmconf/Conf/antisamy.xml ${repoDir}/zm-build/${currentPackage}/opt/zextras/conf/antisamy.xml

  echo -e "\tCopy extensions-extra files of /opt/zextras/"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/extensions-extra/openidconsumer
  cp -rf ${repoDir}/zm-openid-consumer-store/build/dist/. ${repoDir}/zm-build/${currentPackage}/opt/zextras/extensions-extra/openidconsumer
  rm -rf ${repoDir}/zm-build/${currentPackage}/opt/zextras/extensions-extra/openidconsumer/extensions-extra

  echo -e "\tCopy lib files of /opt/zextras/"

  echo -e "\t\tCopy ext files of /opt/zextras/lib/"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/jars
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/libexec
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/clamscanner
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/nginx-lookup
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/openidconsumer
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/zimbraldaputils
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/zm-gql

  cp -f ${repoDir}/zm-clam-scanner-store/build/dist/zm-clam-scanner-store*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/clamscanner/clamscanner.jar
  cp -f ${repoDir}/zm-nginx-lookup-store/build/dist/zm-nginx-lookup-store*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/nginx-lookup/nginx-lookup.jar
  cp -f ${repoDir}/zm-openid-consumer-store/build/dist/guice*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/openidconsumer/
  cp -f ${repoDir}/zm-ldap-utils-store/build/zm-ldap-utils-*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/zimbraldaputils/zimbraldaputils.jar
  cp -f ${repoDir}/zm-gql/build/dist/zm-gql*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/lib/ext/zm-gql/zmgql.jar

  #-------------------- Get wars content (service.war, zimbra.war and zimbraAdmin.war) ---------------------------

  echo "\t\t++++++++++ service.war content ++++++++++"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/service/WEB-INF/lib
  cp ${repoDir}/zm-zimlets/conf/zimbra.tld ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/service/WEB-INF
  cp ${repoDir}/zm-taglib/build/zm-taglib*.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/service/WEB-INF/lib
  cp ${repoDir}/zm-zimlets/build/dist/zimlettaglib.jar ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/service/WEB-INF/lib

  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/zimbra

  echo "\t\t***** robots.txt content *****"
  cp -f ${repoDir}/zm-build/rpmconf/Conf/robots.txt ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/webapps/zimbra/robots.txt

  echo -e "\tCopy log files of /opt/zextras/"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/log
  cp -f ${repoDir}/zm-build/rpmconf/Conf/hotspot_compiler ${repoDir}/zm-build/${currentPackage}/opt/zextras/log/.hotspot_compiler

  echo -e "\tCopy zimlets files of /opt/zextras/"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/zimlets
  zimletsArray=("zm-certificate-manager-admin-zimlet"
    "zm-proxy-config-admin-zimlet"
    "zm-helptooltip-zimlet"
    "zm-viewmail-admin-zimlet")
  for i in "${zimletsArray[@]}"; do
    cp ${repoDir}/${i}/build/zimlet/*.zip ${repoDir}/zm-build/${currentPackage}/opt/zextras/zimlets
  done

  cp -f ${repoDir}/zm-zimlets/build/dist/zimlets/*.zip ${repoDir}/zm-build/${currentPackage}/opt/zextras/zimlets

  echo "\t\t***** Building jetty/common/ *****"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/common/endorsed
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/common/lib

  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/temp
  touch ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/temp/.emptyfile

  echo -e "\tCreate jetty conf"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/modules
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/start.d

  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/jettyrc ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/zimbra.policy.example ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/jetty.xml.production ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/jetty.xml.in
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/webdefault.xml.production ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/webdefault.xml
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/jetty-setuid.xml ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/jetty-setuid.xml
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/spnego/etc/spnego.properties ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/spnego.properties.in
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/spnego/etc/spnego.conf ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/spnego.conf.in
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/spnego/etc/krb5.ini ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/krb5.ini.in
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/modules/*.mod ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/modules
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/modules/*.mod.in ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/modules
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/start.d/*.ini.in ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/start.d
  cp -f ${repoDir}/zm-jetty-conf/conf/jetty/modules/npn/*.mod ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/modules/npn

  cp -f ${repoDir}/zm-zimlets/conf/web.xml.production ${repoDir}/zm-build/${currentPackage}/opt/zextras/jetty_base/etc/zimlet.web.xml.in
}

############################################################################
main "$@"
