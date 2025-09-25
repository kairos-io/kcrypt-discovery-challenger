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

## Selective Enrollment Mode for TPM Attestation

The kcrypt-challenger implements a sophisticated "selective enrollment mode" that solves operational challenges in real-world TPM-based disk encryption deployments. This feature provides flexible attestation management while maintaining strong security guarantees.

### Key Features

✅ **Implemented**: Full selective enrollment with three field states (empty, set, omitted)
✅ **Implemented**: Trust On First Use (TOFU) automatic enrollment
✅ **Implemented**: Secret reuse after SealedVolume recreation  
✅ **Implemented**: PCR re-enrollment for kernel upgrades
✅ **Implemented**: PCR omission for volatile boot stages
✅ **Implemented**: Early quarantine checking with fail-fast behavior

### How Selective Enrollment Works

The system supports two distinct enrollment behaviors:

#### **Initial TOFU Enrollment** (No SealedVolume exists)
- **Store ALL PCRs** provided by the client (don't omit any)
- Create complete attestation baseline from first contact
- Enables full security verification for subsequent attestations

#### **Selective Re-enrollment** (SealedVolume exists with specific fields)
- **Empty values** (`""`) = Accept any value, update the stored value (re-enrollment mode)
- **Set values** (`"abc123..."`) = Enforce exact match (enforcement mode)  
- **Omitted fields** = Skip verification entirely (ignored mode)

**Selective Enrollment Behavior Summary:**

| Field State | Verification | Updates | Use Case |
|-------------|-------------|---------|----------|
| **Empty** (`""`) | ✅ Accept any value | ✅ Update with current | Re-learn after TPM/firmware changes |
| **Set** (`"abc123"`) | ✅ Enforce exact match | ❌ No updates | Strict security enforcement |
| **Omitted** (deleted) | ❌ Skip entirely | ❌ Never re-enrolled | Ignore volatile PCRs (e.g., PCR 11) |

### SealedVolume API Examples

#### **Example 1: Initial TOFU Enrollment**
When no SealedVolume exists, the server automatically creates one with ALL received PCRs:

```yaml
# Server creates this automatically during TOFU enrollment
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
spec:
  TPMHash: "computed-from-client"
  attestation:
    ekPublicKey: "learned-ek"    # Learned from client
    akPublicKey: "learned-ak"    # Learned from client
    pcrValues:
      pcrs:
        "0": "abc123..."         # All received PCRs stored
        "7": "def456..."        
        "11": "ghi789..."        # Including PCR 11 if provided
```

#### **Example 2: Selective Re-enrollment Control**
Operators can control which fields allow re-enrollment:

```yaml
# Operator-controlled selective enforcement
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
spec:
  TPMHash: "required-tpm-hash"   # MUST be set for client matching
  attestation:
    ekPublicKey: ""              # Empty = re-enrollment mode
    akPublicKey: "fixed-ak"      # Set = enforce this value
    pcrValues:
      pcrs:
        "0": ""                  # Empty = re-enrollment mode
        "7": "fixed-value"       # Set = enforce this value
        # "11": omitted          # Omitted = skip entirely
```

### Use Cases Solved

1. **Pure TOFU**: No SealedVolume exists → System learns ALL attestation data from first contact
2. **Static Passphrase Tests**: Create Secret + SealedVolume with TPM hash, let TOFU handle attestation data
3. **Production Manual Setup**: Operators set known passphrases + TPM hashes, system learns remaining security data
4. **Firmware Upgrades**: Set PCR 0 to empty to re-learn after BIOS updates
5. **TPM Replacement**: Set AK/EK fields to empty to re-learn after hardware changes
6. **Flexible Boot Stages**: Omit PCR 11 entirely so users can decrypt during boot AND after full system startup
7. **Kernel Updates**: Omit PCR 11 to avoid quarantine on routine Kairos upgrades

### Practical Operator Workflows

#### **Scenario 1: Reusing Existing Passphrases After SealedVolume Recreation**

**Problem**: An operator needs to recreate a SealedVolume (e.g., after accidental deletion or configuration changes) but wants to keep using the existing passphrase to avoid re-encrypting the disk.

**Solution**: The system automatically reuses existing Kubernetes secrets when available:

```bash
# 1. Operator accidentally deletes SealedVolume
kubectl delete sealedvolume my-encrypted-volume

# 2. Original secret still exists in cluster
kubectl get secret my-encrypted-volume-encrypted-data
# NAME                                  TYPE     DATA   AGE
# my-encrypted-volume-encrypted-data    Opaque   1      5d

# 3. When TPM client reconnects, system detects existing secret
# and reuses the passphrase instead of generating a new one
```

**Behavior**: The system will:
- Detect the existing secret with the same name
- Log: "Secret already exists, reusing existing secret"
- Use the existing passphrase for decryption
- Recreate the SealedVolume with current TPM attestation data
- Maintain continuity without requiring disk re-encryption

#### **Scenario 2: Deliberately Skipping PCRs After Initial Enrollment**

**Problem**: An operator initially enrolls with PCRs 0, 7, and 11, but later realizes PCR 11 changes frequently due to kernel updates and wants to ignore it permanently.

**Solution**: Remove the PCR from the SealedVolume specification:

```bash
# 1. Initial enrollment created SealedVolume with:
# pcrValues:
#   pcrs:
#     "0": "abc123..."
#     "7": "def456..."  
#     "11": "ghi789..."

# 2. Operator edits SealedVolume to remove PCR 11 entirely
kubectl edit sealedvolume my-encrypted-volume
# Remove the "11": "ghi789..." line completely

# 3. Result - omitted PCR 11:
# pcrValues:
#   pcrs:
#     "0": "abc123..."
#     "7": "def456..."
#     # PCR 11 omitted = ignored entirely
```

**Behavior**: The system will:
- Skip PCR 11 verification entirely (no enforcement)
- Never re-enroll PCR 11 in future attestations
- Log: "PCR verification successful using selective enrollment" (without mentioning PCR 11)
- Continue enforcing PCRs 0 and 7 normally

#### **Scenario 3: Manual PCR Selection During Initial Setup**

**Problem**: An operator knows certain PCRs will be unstable and wants to exclude them from the beginning.

**Solution**: Create the initial SealedVolume manually with only desired PCRs:

```yaml
# Create SealedVolume with selective PCR enforcement from the start
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: selective-pcr-volume
spec:
  TPMHash: "known-tpm-hash"
  partitions:
    - label: "encrypted-data"
      secret:
        name: "my-passphrase"
        path: "passphrase"
  attestation:
    ekPublicKey: ""          # Re-enrollment mode
    akPublicKey: ""          # Re-enrollment mode  
    pcrValues:
      pcrs:
        "0": ""              # Re-enrollment mode (will learn)
        "7": ""              # Re-enrollment mode (will learn)
        # "11": omitted      # Skip PCR 11 entirely
```

**Behavior**: The system will:
- Learn and enforce PCRs 0 and 7 on first attestation
- Completely ignore PCR 11 (never verify, never store)
- Allow flexible boot stages without PCR 11 interference

#### **Scenario 4: Kernel Upgrade - Temporary PCR Re-enrollment**

**Problem**: An operator is performing a kernel upgrade and knows PCR 11 will change, but wants to continue enforcing it after the upgrade (unlike permanent omission).

**Solution**: Set the PCR value to empty string to trigger re-enrollment mode:

```bash
# 1. Before kernel upgrade - PCR 11 is currently enforced
kubectl get sealedvolume my-volume -o jsonpath='{.spec.attestation.pcrValues.pcrs.11}'
# Output: "abc123def456..."  (current PCR 11 value)

# 2. Set PCR 11 to empty string to allow re-enrollment
kubectl patch sealedvolume my-volume --type='merge' \
  -p='{"spec":{"attestation":{"pcrValues":{"pcrs":{"11":""}}}}}'

# 3. Perform kernel upgrade and reboot

# 4. After reboot, TPM client reconnects and system learns new PCR 11 value
# Log will show: "Updated PCR value during selective enrollment, pcr: 11"

# 5. Verify new PCR 11 value is now enforced
kubectl get sealedvolume my-volume -o jsonpath='{.spec.attestation.pcrValues.pcrs.11}'
# Output: "new789xyz012..."  (new PCR 11 value after kernel upgrade)
```

**Behavior**: The system will:
- Accept any PCR 11 value on next attestation (re-enrollment mode)
- Update the stored PCR 11 with the new post-upgrade value
- Resume strict PCR 11 enforcement with the new value
- Log: "Updated PCR value during selective enrollment"

**Key Difference from Scenario 2:**
- **Scenario 2 (Omit PCR)**: PCR 11 permanently ignored, never verified again
- **Scenario 4 (Empty PCR)**: PCR 11 temporarily re-enrolled, then enforced with new value

### Security Architecture

- **TPM Hash is mandatory** - prevents multiple clients from matching the same SealedVolume
- **EK verification remains strict** - only AK and PCRs support selective enrollment modes
- **Early quarantine checking** - quarantined TPMs are rejected immediately after authentication
- **Comprehensive logging** - all enrollment events are logged for audit trails
- **Challenge-response authentication** - prevents TPM impersonation attacks

### Quick Reference for Documentation

**Common Operations:**

```bash
# Skip a PCR permanently (never verify again)
kubectl edit sealedvolume my-volume
# Remove the PCR line entirely from pcrValues.pcrs

# Temporarily allow PCR re-enrollment (e.g., before kernel upgrade)
kubectl patch sealedvolume my-volume --type='merge' -p='{"spec":{"attestation":{"pcrValues":{"pcrs":{"11":""}}}}}'

# Re-learn a PCR after hardware change (e.g., PCR 0 after BIOS update)  
kubectl patch sealedvolume my-volume --type='merge' -p='{"spec":{"attestation":{"pcrValues":{"pcrs":{"0":""}}}}}'

# Re-learn AK after TPM replacement
kubectl patch sealedvolume my-volume --type='merge' -p='{"spec":{"attestation":{"akPublicKey":""}}}'

# Check current PCR enforcement status
kubectl get sealedvolume my-volume -o jsonpath='{.spec.attestation.pcrValues.pcrs}' | jq .
```

**Log Messages to Expect:**

- `"Secret already exists, reusing existing secret"` - Passphrase reuse scenario
- `"Updated PCR value during selective enrollment"` - Re-enrollment mode active
- `"PCR verification successful using selective enrollment"` - Omitted PCRs ignored
- `"PCR enforcement mode verification passed"` - Strict enforcement active

## TODO: E2E Testing Coverage for Selective Enrollment

### Priority: High
The selective enrollment implementation is complete, but comprehensive E2E tests are needed to ensure all scenarios work correctly in real-world deployments.

### Required E2E Test Scenarios

#### **1. Basic Enrollment Flows**
- [ ] **Pure TOFU Enrollment**: First-time enrollment with automatic attestation data learning
- [ ] **Manual SealedVolume Creation**: Pre-created SealedVolume with selective field configuration
- [ ] **Secret Reuse**: SealedVolume recreation while preserving existing Kubernetes secrets

#### **2. Quarantine Management**
- [ ] **Quarantined TPM Rejection**: Verify quarantined TPMs are rejected immediately after authentication
- [ ] **Quarantine Flag Enforcement**: Ensure no enrollment or verification occurs for quarantined TPMs
- [ ] **Quarantine Recovery**: Test un-quarantining process (if/when implemented)

#### **3. PCR Management Scenarios**
- [ ] **PCR Re-enrollment**: Set PCR to empty string, verify it learns new value and resumes enforcement
- [ ] **PCR Omission**: Remove PCR entirely, verify it's permanently ignored in future attestations and not re-enrolled.
- [ ] **Kernel Upgrade Workflow**: Full kernel upgrade cycle with PCR 11 re-enrollment
- [ ] **Mixed PCR States**: SealedVolume with some enforced, some re-enrollment, some omitted PCRs

#### **4. AK Management**
- [ ] **AK Re-enrollment**: Set AK to empty string, verify it learns new AK after TPM replacement
- [ ] **AK Enforcement**: Set AK to specific value, verify exact match is required
- [ ] **TPM Replacement**: Full TPM hardware replacement with AK re-learning

#### **5. Security Verification**
- [ ] **PCR Mismatch Detection**: Verify enforcement mode correctly rejects changed PCR values
- [ ] **AK Mismatch Detection**: Verify enforcement mode correctly rejects different AK keys
- [ ] **TPM Impersonation Prevention**: Verify challenge-response prevents replay attacks
- [ ] **Invalid TPM Hash**: Verify clients with wrong TPM hash are rejected

#### **6. Operational Workflows**
- [ ] **Firmware Upgrade**: BIOS/UEFI update changing PCR 0, test re-enrollment workflow
- [ ] **Multi-Partition Support**: Multiple partitions on same TPM with different encryption keys
- [ ] **Namespace Isolation**: Multiple SealedVolumes in different namespaces
- [ ] **Resource Cleanup**: Verify proper cleanup when SealedVolumes/Secrets are deleted

#### **7. Error Handling & Edge Cases**
- [ ] **Network Failures**: Connection drops during various stages of attestation
- [ ] **Malformed Attestation Data**: Invalid EK/AK/PCR data handling
- [ ] **Resource Conflicts**: Multiple clients attempting enrollment simultaneously
- [ ] **Storage Failures**: Kubernetes API failures during SealedVolume updates

#### **8. Performance & Scalability**
- [ ] **Concurrent Attestations**: Multiple TPMs requesting passphrases simultaneously
- [ ] **Large PCR Sets**: Attestation with many PCRs (0-23)
- [ ] **Long-Running Stability**: Extended operation over multiple hours/days

#### **9. Logging & Observability**
- [ ] **Audit Trail Verification**: Ensure all security events are properly logged
- [ ] **Log Message Accuracy**: Verify expected log messages appear for each scenario
- [ ] **Metrics Collection**: Performance and security metrics are captured correctly

#### **10. Compatibility Testing**
- [ ] **Multiple TPM Versions**: TPM 1.2 vs TPM 2.0 compatibility (if supported)
- [ ] **Different Kernel Versions**: Various PCR 11 behaviors across kernel versions
- [ ] **Hardware Variations**: Different TPM chip manufacturers and models

### Test Environment Requirements

- **Real TPM Hardware**: Software TPM simulators may not catch hardware-specific issues
- **Kernel Build Pipeline**: Ability to test actual kernel upgrades and PCR changes
- **Multi-Node Clusters**: Test distributed scenarios and namespace isolation
- **Network Partitioning**: Test resilience under network failures
- **Performance Monitoring**: Metrics collection for scalability validation

### Success Criteria

All E2E tests must pass consistently across:
- Different hardware configurations (various TPM chips)
- Multiple kernel versions (to test PCR 11 variability) 
- Various cluster configurations (single-node, multi-node)
- Different load conditions (single client, concurrent clients)

Completing this E2E test suite will provide confidence that the selective enrollment system works reliably in production environments.
