#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Shell script to create mta package

#-------------------- Configuration ---------------------------

currentScript=$(basename $0 | cut -d "." -f 1)                 # carbonio-mta
currentPackage=$(echo ${currentScript}build | cut -d "-" -f 2) # mtabuild

#-------------------- Build Package ---------------------------
main() {
  echo -e "\tCreate package directories"
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/common/conf
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/amavisd/mysql
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/altermime
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/cbpolicyd/db
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/clamav
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/opendkim
  mkdir -p ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/postfix

  echo -e "\tCopy package files"
  cp ${repoDir}/zm-postfix/conf/postfix/master.cf.in ${repoDir}/zm-build/${currentPackage}/opt/zextras/common/conf/master.cf.in
  cp ${repoDir}/zm-postfix/conf/postfix/tag_as_foreign.re.in ${repoDir}/zm-build/${currentPackage}/opt/zextras/common/conf/tag_as_foreign.re.in
  cp ${repoDir}/zm-postfix/conf/postfix/tag_as_originating.re.in ${repoDir}/zm-build/${currentPackage}/opt/zextras/common/conf/tag_as_originating.re.in
  cp -f ${repoDir}/zm-amavis/conf/amavisd/mysql/antispamdb.sql ${repoDir}/zm-build/${currentPackage}/opt/zextras/data/amavisd/mysql/antispamdb.sql
}

#-------------------- Util Functions ---------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/utils.sh"

############################################################################
main "$@"
