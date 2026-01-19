#!/bin/bash
# Copyright 2025 Alibaba Group Holding Ltd.
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

set -euxo pipefail

TAG=${TAG:-latest}

# build execd image locally
cd components/execd && docker build -t opensandbox/execd:local .
cd ../..

# prepare required images from registry
docker pull opensandbox/code-interpreter:${TAG}

# setup server
echo "-------- Eval test images --------"
docker images
cd server
uv sync && uv run python -m src.main > server.log 2>&1 &
cd ..

# wait for server
sleep 10

cd sdks/sandbox/kotlin
./gradlew publishToMavenLocal
cd ../../../

cd sdks/code-interpreter/kotlin
./gradlew publishToMavenLocal -PuseMavenLocal
cd ../../../

# run Java e2e
cd tests/java
./gradlew test
