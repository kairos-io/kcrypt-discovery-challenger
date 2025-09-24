<h1 align="center">
  <br>
     <img width="184" alt="kairos-white-column 5bc2fe34" src="https://user-images.githubusercontent.com/2420543/193010398-72d4ba6e-7efe-4c2e-b7ba-d3a826a55b7d.png"><br>
    Kcrypt challenger
<br>
</h1>

<h3 align="center">Kcrypt TPM challenger</h3>
<p align="center">
  <a href="https://opensource.org/licenses/">
    <img src="https://img.shields.io/badge/licence-APL2-brightgreen"
         alt="license">
  </a>
  <a href="https://github.com/kairos-io/kcrypt-challenger/issues"><img src="https://img.shields.io/github/issues/kairos-io/kcrypt-challenger"></a>
  <a href="https://kairos.io/docs/" target=_blank> <img src="https://img.shields.io/badge/Documentation-blue"
         alt="docs"></a>
  <img src="https://img.shields.io/badge/made%20with-Go-blue">
  <img src="https://goreportcard.com/badge/github.com/kairos-io/kcrypt-challenger" alt="go report card" />
  <a href="https://github.com/kairos-io/kcrypt-challenger/actions/workflows/e2e-tests.yml?query=branch%3Amain"> <img src="https://github.com/kairos-io/kcrypt-challenger/actions/workflows/e2e-tests.yml/badge.svg?branch=main"></a>
</p>


With Kairos you can build immutable, bootable Kubernetes and OS images for your edge devices as easily as writing a Dockerfile. Optional P2P mesh with distributed ledger automates node bootstrapping and coordination. Updating nodes is as easy as CI/CD: push a new image to your container registry and let secure, risk-free A/B atomic upgrades do the rest.


<table>
<tr>
<th align="center">
<img width="640" height="1px">
<p> 
<small>
Documentation
</small>
</p>
</th>
<th align="center">
<img width="640" height="1">
<p> 
<small>
Contribute
</small>
</p>
</th>
</tr>
<tr>
<td>

 📚 [Getting started with Kairos](https://kairos.io/docs/getting-started) <br> :bulb: [Examples](https://kairos.io/docs/examples) <br> :movie_camera: [Video](https://kairos.io/docs/media/) <br> :open_hands:[Engage with the Community](https://kairos.io/community/)
  
</td>
<td>
  
🙌[ CONTRIBUTING.md ]( https://github.com/kairos-io/kairos/blob/master/CONTRIBUTING.md ) <br> :raising_hand: [ GOVERNANCE ]( https://github.com/kairos-io/kairos/blob/master/GOVERNANCE.md ) <br>:construction_worker:[Code of conduct](https://github.com/kairos-io/kairos/blob/master/CODE_OF_CONDUCT.md) 
  
</td>
</tr>
</table>

| :exclamation: | This is experimental! |
|-|:-|

This is the Kairos kcrypt-challenger Kubernetes Native Extension. 

## Usage

See the documentation in our website: https://kairos.io/docs/advanced/partition_encryption/.

### TPM NV Memory Cleanup

⚠️ **DANGER**: This command removes encryption passphrases from TPM memory!
⚠️ **If you delete the wrong index, your encrypted disk may become UNBOOTABLE!**

During development and testing, the kcrypt-challenger may store passphrases in TPM non-volatile (NV) memory. These passphrases persist across reboots and can accumulate over time, taking up space in the TPM.

To clean up TPM NV memory used by the challenger:

```bash
# Clean up the default NV index (respects config or defaults to 0x1500000)
kcrypt-discovery-challenger cleanup

# Clean up a specific NV index
kcrypt-discovery-challenger cleanup --nv-index=0x1500001

# Clean up with specific TPM device
kcrypt-discovery-challenger cleanup --tpm-device=/dev/tpmrm0
```

**Safety Features:**
- By default, the command shows warnings and prompts for confirmation
- You must type "yes" to proceed with deletion
- Use `--i-know-what-i-am-doing` flag to skip the prompt (not recommended)

**Note**: This command uses native Go TPM libraries and requires appropriate permissions to access the TPM device.

## Installation

To install, use helm:

```
# Adds the kairos repo to helm
$ helm repo add kairos https://kairos-io.github.io/helm-charts
"kairos" has been added to your repositories
$ helm repo update                                        
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "kairos" chart repository
Update Complete. ⎈Happy Helming!⎈

# Install the CRD chart
$ helm install kairos-crd kairos/kairos-crds
NAME: kairos-crd
LAST DEPLOYED: Tue Sep  6 20:35:34 2022
NAMESPACE: default
STATUS: deployed
REVISION: 1
TEST SUITE: None

# Installs challenger
$ helm install kairos-challenger kairos/kcrypt-challenger
```

## TODO: Implement Selective Enrollment Mode for Attestation Data

### Problem Statement

Currently, the TPM attestation system faces operational challenges in real-world deployments:

1. **Test Complexity**: Tests require manually creating SealedVolumes with complex mock attestation data (EK, AK, PCR values)
2. **Upgrade Compatibility**: Kernel upgrades change PCR values, causing TPM quarantine and disk inaccessibility  
3. **Operational Flexibility**: No mechanism for operators to reset/update attestation data after TPM replacement, firmware upgrades, or key rotation

### Proposed Solution: Selective Enrollment Mode

Implement a "selective enrollment mode" with two distinct behaviors:

#### **Initial TOFU Enrollment** (No SealedVolume exists)
- **Store ALL PCRs** provided by the client (don't omit any)
- Create complete attestation baseline from first contact
- Enables full security verification for subsequent attestations

#### **Selective Re-enrollment** (SealedVolume exists with specific fields)
- **Empty values** (`""`) = Accept any value, update the stored value
- **Set values** (`"abc123..."`) = Enforce exact match
- **Omitted fields** = Skip verification entirely (allows flexibility)

### Required Implementation Changes

#### 1. **SealedVolume API Enhancement**
```yaml
# Example 1: Initial TOFU (no SealedVolume exists)
# Server creates this automatically with ALL received PCRs:
spec:
  TPMHash: "computed-from-client"
  attestation:
    ekPublicKey: "learned-ek"
    akPublicKey: "learned-ak"  
    pcrValues:
      pcrs:
        "0": "abc123..."        # All received PCRs stored
        "7": "def456..."        
        "11": "ghi789..."       # Including PCR 11 if provided

# Example 2: Selective Re-enrollment (operator control)
spec:
  TPMHash: "required-tmp-hash"  # MUST be set for client matching
  attestation:
    ekPublicKey: ""             # Empty = re-enrollment mode
    akPublicKey: "fixed-ak"     # Set = enforce this value
    pcrValues:
      pcrs:
        "0": ""                 # Empty = re-enrollment mode
        "7": "fixed-value"      # Set = enforce this value
        # "11": omitted         # Omitted = skip entirely (flexible boot stages)
```

#### 2. **Server Logic Updates**
- **TOFU Logic**: When no SealedVolume exists, store ALL received PCRs (don't omit any)
- **Re-enrollment Logic**: 
  - Modify `verifyAKMatch()` to handle empty AK fields as re-enrollment mode
  - Modify `verifyPCRValues()` to handle empty PCR values as re-enrollment mode
  - Handle omitted PCR fields as "skip verification entirely"
- Add logic to update SealedVolume specs when learning new values
- Ensure TPM hash is always required and validated for client matching

#### 3. **Test Simplification**
Replace complex mock attestation data in tests with simple enrollment mode:
```yaml
# tests/encryption_test.go - remote-static test
spec:
  TPMHash: "computed-from-vm"   # Get from /system/discovery/kcrypt-discovery-challenger
  partitions:
    - label: COS_PERSISTENT
      secret: {name: "static-passphrase", path: "pass"}
  attestation: {}               # Full enrollment mode
```

### Use Cases Solved

1. **Pure TOFU**: No SealedVolume exists → System learns ALL attestation data from first contact
2. **Static Passphrase Tests**: Create Secret + SealedVolume with TPM hash, let TOFU handle attestation data
3. **Production Manual Setup**: Operators set known passphrases + TPM hashes, system learns remaining security data
4. **Firmware Upgrades**: Set PCR 0 to empty to re-learn after BIOS updates
5. **TPM Replacement**: Set AK/EK fields to empty to re-learn after hardware changes
6. **Flexible Boot Stages**: Omit PCR 11 entirely so users can decrypt during boot AND after full system startup
7. **Kernel Updates**: Omit PCR 11 to avoid quarantine on routine Kairos upgrades

### Critical Implementation Notes

- **TPM Hash MUST remain mandatory** - without it, multiple clients would match the same SealedVolume
- **EK verification should remain strict** - only AK and PCRs should support enrollment mode
- **Add proper logging** for enrollment events for audit trails
- **Consider rate limiting** to prevent abuse of enrollment mode
- **Update documentation** with operational procedures for each use case

### Priority: High
This blocks current test failures and addresses fundamental operational challenges for production deployments.
