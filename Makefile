# Copyright 2020 The Kubernetes Authors.
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


DEBUG ?= "false"
TEST ?= "^[\s\S]+$$"

.PHONY: all build clean install

all: clean build install

clean:
	go clean -r -x
	-rm -rf _output

build:
	go build ./iscsi/
	go build -o _output/example ./example/main.go

install:
	go install ./iscsi/

test:
ifeq ($(DEBUG), true)
	@export DEBUG
	go test ./iscsi/ -v -run $(TEST)
else
	go test ./iscsi
endif

