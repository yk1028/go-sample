# Gcp kms signing server

### Todo
- [x] publickey
- [x] signature
- [x] logging
- [ ] swagger

### Key
- GCP KMS HSM
  - `./keyinfo.json` 경로에 아래와 같은 형태의 key정보로 Gcp kms의 key의 접근 경로 관리
``` json
{
    "gcpkms" : {
        "relayer1" : "projects/rock-heaven-340205/locations/global/keyRings/xpla-test/cryptoKeys/go-test-key/cryptoKeyVersions/1",
        "relayer2" : "projects/rock-heaven-340205/locations/global/keyRings/xpla-test/cryptoKeys/go-test-key-2/cryptoKeyVersions/1",
        "relayer3" : "projects/rock-heaven-340205/locations/global/keyRings/xpla-test/cryptoKeys/go-test-key-3/cryptoKeyVersions/1"
    }
}
```
- Cosmos Sdk keyring file
  - `./keyring-file` 디렉토리 안에 keyring과 key정보를 가진 파일(keyhash, .address, .info)을 추가하면 cosmos sdk의 keyring file 방식으로 key 추가 가능
  - 최초 실행시 keyring passphrase 입력 필요