#!/bin/bash

#
#
# 
# This file contains Original Code and/or Modifications of Original Code
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# file.
# 
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
# 
#
# list_supported.sh <directory with .exports files> <lower case architecture> <target file>

CONFIG_DIR=$1 
ARCH=$2
TARGET_FILE=$3

SUPPORTED_KPI_FILES=( BSDKernel Mach IOKit Libkern )

rm -f ${TARGET_FILE}

if [ ${ARCH} == "all" ]
then 
	echo "The following symbols are considered sustainable KPI on all architectures." >> ${TARGET_FILE}
	echo "Note that symbols may be exported by some (or all) architectures individually." >> ${TARGET_FILE}
else
	echo "The following symbols are considered sustainable KPI on architecture ${ARCH}." >> ${TARGET_FILE}
fi
echo  >> ${TARGET_FILE}

for (( i = 0 ; i < ${#SUPPORTED_KPI_FILES[@]} ; i++ ))
do
	echo "Exported by ${DEPENDENCY_NAMES[i]}:" >> ${TARGET_FILE}
	echo >> ${TARGET_FILE}
	if [  ${ARCH} == "all" ]
	then
		cat "${CONFIG_DIR}/${SUPPORTED_KPI_FILES[i]}.exports" | sed "s/^_//" | sed "s/:.*//" | sort >> ${TARGET_FILE}
	else
		cat "${CONFIG_DIR}/${SUPPORTED_KPI_FILES[i]}.${ARCH}.exports" | sed "s/^_//" | sed "s/:.*//" | sort  >> ${TARGET_FILE}
	fi
	echo >> ${TARGET_FILE}
done
