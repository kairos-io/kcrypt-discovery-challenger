package constants

const TPMSecret = "tpm"
const GeneratedByKey = "generated_by"

// TPM NV Index constants for storing encrypted data
// Using 0x1500000+ range to avoid reserved TPM manufacturer ranges (0x00000000-0x003FFFFF)
const LocalPassphraseNVIndex = "0x1500000" // For storing encrypted LUKS passphrase (offline mode)
// Note: AKBlobNVIndex removed - using transient AKs now, no persistent AK storage needed
