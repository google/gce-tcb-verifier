# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/bin/sh

keydir=$(mktemp -d)
go run ./testing/nonprod/gcetcb bootstrap \
  --key_dir "${keydir}" \
  --bucket_root "${keydir}" \
  --bucket devkeys \
  --root_path root.crt \
  --cert_dir=./
ls "${keydir}"
ls "${keydir}/devkeys"
mv "${keydir}"/*.pem ./testing/devkeys/
mv "${keydir}"/devkeys/root.crt ./testing/devkeys/
mv "${keydir}"/devkeys/GCE-uefi-signer-2.crt ./testing/devkeys/primarySigningKey.crt
