#!/bin/bash
# Copyright 2022 Sony Semiconductor Solutions Corp. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

echo "#### run test app with ppl sample wasm file ####"

# DEBUG_PORT="127.0.0.1:1234"  # lldb debug port

DEBUGGER=none

# Parameter check

while getopts :df:o:p:t: option
do
  case $option in
    d)
      DEBUGGER="-d";;
    f);;
    o);;
    p);;
    t);;
    ?);;
  esac
done

LOADER=${PWD}/build/loader/loader

echo "DEBUGGER ${DEBUGGER}"

if [ $DEBUGGER = "-d" ]; then
   echo "PROC: ${LOADER} -g $@"

   ${LOADER} -g $@
else
   echo "PROC: ${LOADER} $@"

   ${LOADER} $@
fi
