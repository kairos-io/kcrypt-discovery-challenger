// [✓] Setup a cluster
// [✓] install crds on it
// - run the server locally
// - make requests to the server to see if we can get passphrases back
package challenger

import (
	"net/http"
	"net/http/httptest"

	"github.com/go-logr/logr"
	"github.com/google/go-attestation/attest"
	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("challenger", func() {
	Describe("findSecretFor", func() {
		var requestData PassphraseRequestData
		var volumeList *keyserverv1alpha1.SealedVolumeList

		BeforeEach(func() {
			requestData = PassphraseRequestData{
				TPMHash:    "1234",
				DeviceName: "/dev/sda1",
				UUID:       "sda1_uuid",
				Label:      "COS_PERSISTENT",
			}
		})

		When("a sealedvolume matching the label exists", func() {
			BeforeEach(func() {
				volumeList = volumeListWithPartitionSpec(
					keyserverv1alpha1.PartitionSpec{
						Label:      requestData.Label,
						DeviceName: "not_matching",
						UUID:       "not_matching",
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "the_secret",
							Path: "the_path",
						}})
			})

			It("returns the sealed volume data", func() {
				volumeData, _ := findVolumeFor(requestData, volumeList)
				Expect(volumeData).ToNot(BeNil())
				Expect(volumeData.Quarantined).To(BeFalse())
				Expect(volumeData.SecretName).To(Equal("the_secret"))
				Expect(volumeData.SecretPath).To(Equal("the_path"))
			})
		})

		When("a sealedvolume with empty field exists", func() {
			BeforeEach(func() {
				volumeList = volumeListWithPartitionSpec(
					keyserverv1alpha1.PartitionSpec{
						Label:      "",
						DeviceName: "not_matching",
						UUID:       "not_matching",
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "the_secret",
							Path: "the_path",
						}})

				requestData = PassphraseRequestData{
					TPMHash:    "1234",
					Label:      "",
					DeviceName: "/dev/sda1",
					UUID:       "sda1_uuid",
				}
			})

			It("doesn't match a request with an empty field", func() {
				volumeData, _ := findVolumeFor(requestData, volumeList)
				Expect(volumeData).To(BeNil())
			})
		})

		When("a sealedvolume matching the device name exists", func() {
			BeforeEach(func() {
				volumeList = volumeListWithPartitionSpec(
					keyserverv1alpha1.PartitionSpec{
						Label:      "not_matching",
						DeviceName: requestData.DeviceName,
						UUID:       "not_matching",
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "the_secret",
							Path: "the_path",
						}})
			})

			It("returns the sealed volume data", func() {
				volumeData, _ := findVolumeFor(requestData, volumeList)
				Expect(volumeData).ToNot(BeNil())
				Expect(volumeData.Quarantined).To(BeFalse())
				Expect(volumeData.SecretName).To(Equal("the_secret"))
				Expect(volumeData.SecretPath).To(Equal("the_path"))
			})
		})

		When("a sealedvolume matching the UUID exists", func() {
			BeforeEach(func() {
				volumeList = volumeListWithPartitionSpec(
					keyserverv1alpha1.PartitionSpec{
						Label:      "not_matching",
						DeviceName: "not_matching",
						UUID:       requestData.UUID,
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "the_secret",
							Path: "the_path",
						}})
			})

			It("returns the sealed volume data", func() {
				volumeData, _ := findVolumeFor(requestData, volumeList)
				Expect(volumeData).ToNot(BeNil())
				Expect(volumeData.Quarantined).To(BeFalse())
				Expect(volumeData.SecretName).To(Equal("the_secret"))
				Expect(volumeData.SecretPath).To(Equal("the_path"))
			})
		})

		When("a matching sealedvolume doesn't exist", func() {
			BeforeEach(func() {
				volumeList = volumeListWithPartitionSpec(
					keyserverv1alpha1.PartitionSpec{
						Label:      "not_matching",
						DeviceName: "not_matching",
						UUID:       "not_matching",
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "the_secret",
							Path: "the_path",
						}})
			})

			It("returns nil sealedVolumeData", func() {
				volumeData, _ := findVolumeFor(requestData, volumeList)
				Expect(volumeData).To(BeNil())
			})
		})
	})

	Describe("Selective Enrollment Mode", func() {
		var logger logr.Logger

		BeforeEach(func() {
			logger = logr.Discard()
		})

		Describe("verifyAKMatch with selective enrollment", func() {
			var currentAK *attest.AttestationParameters
			var expectedAKPEM string
			const mockAKPublicKey = "mock-ak-public-key"

			BeforeEach(func() {
				// Mock current AK parameters - in real implementation this would come from TPM
				currentAK = &attest.AttestationParameters{
					Public:                  []byte(mockAKPublicKey),
					UseTCSDActivationFormat: false,
					CreateData:              []byte("mock-create-data"),
					CreateAttestation:       []byte("mock-create-attestation"),
					CreateSignature:         []byte("mock-create-signature"),
				}

				// Generate the expected PEM encoding from the plain text constant
				var err error
				expectedAKPEM, err = encodeAKToPEM(currentAK)
				Expect(err).To(BeNil())
			})

			When("stored AK is empty (re-enrollment mode)", func() {
				It("should store the current AK value during re-enrollment", func() {
					attestation := &keyserverv1alpha1.AttestationSpec{
						AKPublicKey: "", // Empty = re-enrollment mode
					}

					// Before re-enrollment: AK should be empty
					Expect(attestation.AKPublicKey).To(Equal(""))

					// Re-enrollment should store the current AK
					err := updateAttestationDataSelective(attestation, currentAK, nil, logger)
					Expect(err).To(BeNil())

					// After re-enrollment: AK should contain the exact expected PEM value
					Expect(attestation.AKPublicKey).To(Equal(expectedAKPEM))
				})

				It("should accept any AK, store it during re-enrollment, then enforce exact match", func() {
					attestation := &keyserverv1alpha1.AttestationSpec{
						AKPublicKey: "", // Start in re-enrollment mode
					}
					sealedVolume := &keyserverv1alpha1.SealedVolume{
						Spec: keyserverv1alpha1.SealedVolumeSpec{
							Attestation: attestation,
						},
					}

					// Step 1: Verification should pass with any AK (re-enrollment mode)
					err := verifyAKMatchSelective(sealedVolume, currentAK, logger)
					Expect(err).To(BeNil())

					// Step 2: Re-enroll - store the AK
					err = updateAttestationDataSelective(attestation, currentAK, nil, logger)
					Expect(err).To(BeNil())

					// Step 3: Now we should be in enforcement mode - same AK should pass
					err = verifyAKMatchSelective(sealedVolume, currentAK, logger)
					Expect(err).To(BeNil())

					// Step 4: Different AK should now fail (enforcement mode)
					differentAK := &attest.AttestationParameters{
						Public: []byte("different-ak-key"),
					}
					err = verifyAKMatchSelective(sealedVolume, differentAK, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("AK public key does not match"))
				})
			})

			When("stored AK is set (enforcement mode)", func() {
				It("should enforce exact match", func() {
					// Create a specific AK PEM that won't match our mock
					storedAKPEM := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n-----END PUBLIC KEY-----"
					attestation := &keyserverv1alpha1.AttestationSpec{
						AKPublicKey: storedAKPEM,
					}
					sealedVolume := &keyserverv1alpha1.SealedVolume{
						Spec: keyserverv1alpha1.SealedVolumeSpec{
							Attestation: attestation,
						},
					}

					err := verifyAKMatchSelective(sealedVolume, currentAK, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("AK public key does not match"))
				})
			})

			When("no attestation data exists", func() {
				It("should return error", func() {
					sealedVolume := &keyserverv1alpha1.SealedVolume{
						Spec: keyserverv1alpha1.SealedVolumeSpec{
							Attestation: nil,
						},
					}

					err := verifyAKMatchSelective(sealedVolume, currentAK, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("no attestation data"))
				})
			})
		})

		Describe("verifyPCRValuesSelective", func() {
			var currentPCRs *keyserverv1alpha1.PCRValues
			const expectedPCR0 = "abc123def456"
			const expectedPCR7 = "ghi789jkl012"
			const expectedPCR11 = "mno345pqr678"

			BeforeEach(func() {
				currentPCRs = &keyserverv1alpha1.PCRValues{
					PCRs: map[string]string{
						"0":  expectedPCR0,
						"7":  expectedPCR7,
						"11": expectedPCR11,
					},
				}
			})

			When("stored PCR values are empty (re-enrollment mode)", func() {
				It("should accept any PCR values during verification", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0":  "", // Empty = re-enrollment mode
							"7":  "", // Empty = re-enrollment mode
							"11": "", // Empty = re-enrollment mode
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, currentPCRs, logger)
					Expect(err).To(BeNil())
				})

				It("should store the current PCR values during re-enrollment", func() {
					attestation := &keyserverv1alpha1.AttestationSpec{
						PCRValues: &keyserverv1alpha1.PCRValues{
							PCRs: map[string]string{
								"0":  "", // Empty = re-enrollment mode
								"7":  "", // Empty = re-enrollment mode
								"11": "", // Empty = re-enrollment mode
							},
						},
					}

					// Before re-enrollment: PCRs should be empty
					Expect(attestation.PCRValues.PCRs["0"]).To(Equal(""))
					Expect(attestation.PCRValues.PCRs["7"]).To(Equal(""))
					Expect(attestation.PCRValues.PCRs["11"]).To(Equal(""))

					// Re-enrollment should store the current PCR values
					err := updateAttestationDataSelective(attestation, nil, currentPCRs, logger)
					Expect(err).To(BeNil())

					// After re-enrollment: PCRs should be stored with exact expected values
					Expect(attestation.PCRValues.PCRs["0"]).To(Equal(expectedPCR0))
					Expect(attestation.PCRValues.PCRs["7"]).To(Equal(expectedPCR7))
					Expect(attestation.PCRValues.PCRs["11"]).To(Equal(expectedPCR11))
				})

				It("should transition from re-enrollment mode to enforcement mode", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0": "", // Start in re-enrollment mode
						},
					}

					// Create a limited current PCR set (only PCR0) to test selective enrollment
					limitedCurrentPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0": expectedPCR0, // Only provide PCR0
						},
					}

					// Step 1: Should accept any PCR values (re-enrollment mode)
					err := verifyPCRValuesSelective(storedPCRs, limitedCurrentPCRs, logger)
					Expect(err).To(BeNil())

					// Step 2: Re-enroll - store the PCR value (should only update the empty PCR0)
					attestation := &keyserverv1alpha1.AttestationSpec{
						PCRValues: storedPCRs,
					}
					err = updateAttestationDataSelective(attestation, nil, limitedCurrentPCRs, logger)
					Expect(err).To(BeNil())

					// Verify PCR0 was enrolled and no other PCRs were added
					Expect(storedPCRs.PCRs["0"]).To(Equal(expectedPCR0))
					Expect(storedPCRs.PCRs).To(HaveLen(1)) // Should still only have PCR0

					// Step 3: Now should be in enforcement mode - same PCR should pass
					err = verifyPCRValuesSelective(storedPCRs, limitedCurrentPCRs, logger)
					Expect(err).To(BeNil())

					// Step 4: Different PCR should now fail (enforcement mode)
					differentPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0": "different_value",
						},
					}
					err = verifyPCRValuesSelective(storedPCRs, differentPCRs, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("PCR0 changed"))
				})
			})

			When("stored PCR values are set (enforcement mode)", func() {
				It("should enforce exact match for set values", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0":  "abc123def456",    // Matches current
							"7":  "different_value", // Different from current
							"11": "mno345pqr678",    // Matches current
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, currentPCRs, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("PCR7 changed"))
				})

				It("should pass when all set values match", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0":  "abc123def456", // Matches current
							"7":  "ghi789jkl012", // Matches current
							"11": "mno345pqr678", // Matches current
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, currentPCRs, logger)
					Expect(err).To(BeNil())
				})
			})

			When("PCR fields are omitted (skip verification)", func() {
				It("should skip verification for omitted PCRs entirely", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0": "abc123def456", // Present and matches
							"7": "ghi789jkl012", // Present and matches
							// "11" is omitted entirely = skip verification
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, currentPCRs, logger)
					Expect(err).To(BeNil())
				})
			})

			When("mixed selective and enforcement mode", func() {
				It("should handle combination of empty, set, and omitted PCRs", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0":  "",             // Empty = re-enrollment mode
							"7":  "ghi789jkl012", // Set = enforcement mode (matches)
							"14": "any_value",    // Set but PCR14 not in current (should fail)
							// "11" omitted = skip verification
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, currentPCRs, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("PCR14"))
				})
			})

			When("no stored PCR values exist", func() {
				It("should accept any current PCR values", func() {
					err := verifyPCRValuesSelective(nil, currentPCRs, logger)
					Expect(err).To(BeNil())
				})
			})

			When("no current PCR values provided", func() {
				It("should pass if no stored values either", func() {
					err := verifyPCRValuesSelective(nil, nil, logger)
					Expect(err).To(BeNil())
				})

				It("should fail if stored values expect specific PCRs", func() {
					storedPCRs := &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0": "abc123def456",
						},
					}

					err := verifyPCRValuesSelective(storedPCRs, nil, logger)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("no current PCR values"))
				})
			})
		})

		Describe("updateAttestationData for selective enrollment", func() {
			It("should update empty fields with current values", func() {
				currentAK := &attest.AttestationParameters{
					Public: []byte("new-ak-public-key"),
				}
				currentPCRs := &keyserverv1alpha1.PCRValues{
					PCRs: map[string]string{
						"0":  "new_pcr0_value",
						"7":  "new_pcr7_value",
						"11": "new_pcr11_value",
					},
				}

				attestation := &keyserverv1alpha1.AttestationSpec{
					AKPublicKey: "", // Empty = should be updated
					PCRValues: &keyserverv1alpha1.PCRValues{
						PCRs: map[string]string{
							"0":  "",                 // Empty = should be updated
							"7":  "fixed_pcr7_value", // Set = should NOT be updated
							"11": "",                 // Empty = should be updated
						},
					},
				}

				err := updateAttestationDataSelective(attestation, currentAK, currentPCRs, logger)
				Expect(err).To(BeNil())

				// AK should be updated
				Expect(attestation.AKPublicKey).ToNot(BeEmpty())

				// PCR0 should be updated (was empty)
				Expect(attestation.PCRValues.PCRs["0"]).To(Equal("new_pcr0_value"))

				// PCR7 should NOT be updated (was set)
				Expect(attestation.PCRValues.PCRs["7"]).To(Equal("fixed_pcr7_value"))

				// PCR11 should be updated (was empty)
				Expect(attestation.PCRValues.PCRs["11"]).To(Equal("new_pcr11_value"))
			})

			It("should demonstrate AK re-enrollment workflow", func() {
				// Step 1: Start with empty AK (re-enrollment mode)
				originalAK := ""
				attestation := &keyserverv1alpha1.AttestationSpec{
					AKPublicKey: originalAK, // Empty = re-enrollment mode
				}

				// Step 2: Current AK from client
				currentAK := &attest.AttestationParameters{
					Public: []byte("client-provided-ak-key"),
				}

				// Step 3: Verification should pass (empty stored AK accepts any)
				sealedVolume := &keyserverv1alpha1.SealedVolume{
					Spec: keyserverv1alpha1.SealedVolumeSpec{
						Attestation: attestation,
					},
				}
				err := verifyAKMatchSelective(sealedVolume, currentAK, logger)
				Expect(err).To(BeNil())

				// Step 4: Update should store the new AK (this is the re-enrollment)
				err = updateAttestationDataSelective(attestation, currentAK, nil, logger)
				Expect(err).To(BeNil())

				// Step 5: Verify the AK was actually enrolled (stored)
				Expect(attestation.AKPublicKey).ToNot(BeEmpty())
				Expect(attestation.AKPublicKey).ToNot(Equal(originalAK))

				// Step 6: Future verification should now require exact match
				err = verifyAKMatchSelective(sealedVolume, currentAK, logger)
				Expect(err).To(BeNil()) // Should still pass with same AK

				// Step 7: Different AK should now fail (enforcement mode)
				differentAK := &attest.AttestationParameters{
					Public: []byte("different-ak-key"),
				}
				err = verifyAKMatchSelective(sealedVolume, differentAK, logger)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("AK public key does not match"))
			})
		})

		Describe("Initial TOFU Enrollment behavior", func() {
			It("should store ALL provided PCRs during initial enrollment", func() {
				clientPCRs := &keyserverv1alpha1.PCRValues{
					PCRs: map[string]string{
						"0":  "pcr0_value",
						"1":  "pcr1_value",
						"2":  "pcr2_value",
						"7":  "pcr7_value",
						"11": "pcr11_value",
						"14": "pcr14_value",
					},
				}

				attestation := createInitialTOFUAttestation(nil, clientPCRs, logger)

				// All provided PCRs should be stored
				Expect(attestation.PCRValues).ToNot(BeNil())
				Expect(attestation.PCRValues.PCRs).To(HaveLen(6))
				Expect(attestation.PCRValues.PCRs["0"]).To(Equal("pcr0_value"))
				Expect(attestation.PCRValues.PCRs["1"]).To(Equal("pcr1_value"))
				Expect(attestation.PCRValues.PCRs["2"]).To(Equal("pcr2_value"))
				Expect(attestation.PCRValues.PCRs["7"]).To(Equal("pcr7_value"))
				Expect(attestation.PCRValues.PCRs["11"]).To(Equal("pcr11_value"))
				Expect(attestation.PCRValues.PCRs["14"]).To(Equal("pcr14_value"))
			})

			It("should not filter or omit any PCRs during TOFU", func() {
				// Test that even "sensitive" PCRs like PCR11 are stored
				clientPCRs := &keyserverv1alpha1.PCRValues{
					PCRs: map[string]string{
						"11": "kernel_pcr_value", // Previously filtered out
						"12": "other_pcr_value",
					},
				}

				attestation := createInitialTOFUAttestation(nil, clientPCRs, logger)

				Expect(attestation.PCRValues.PCRs).To(HaveKey("11"))
				Expect(attestation.PCRValues.PCRs).To(HaveKey("12"))
				Expect(attestation.PCRValues.PCRs["11"]).To(Equal("kernel_pcr_value"))
			})
		})
	})

	Describe("handleTPMAttestation functions", func() {
		Describe("establishAttestationConnection", func() {
			var mockResponseWriter *httptest.ResponseRecorder
			var mockRequest *http.Request
			var logger logr.Logger

			BeforeEach(func() {
				logger = logr.Discard()
				mockResponseWriter = httptest.NewRecorder()
				mockRequest = httptest.NewRequest("GET", "/test", nil)

				// Set partition headers
				mockRequest.Header.Set("label", "COS_PERSISTENT")
				mockRequest.Header.Set("name", "/dev/sda1")
				mockRequest.Header.Set("uuid", "test-uuid-123")
			})

			It("should return error when WebSocket upgrade fails", func() {
				// This test checks the error behavior when WebSocket upgrade fails
				conn, partition, err := establishAttestationConnection(mockResponseWriter, mockRequest, logger)

				// WebSocket upgrade should fail with regular HTTP request
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("upgrade"))
				Expect(conn).To(BeNil())

				// When upgrade fails, partition info is not extracted (function returns early)
				Expect(partition.Label).To(Equal(""))
				Expect(partition.DeviceName).To(Equal(""))
				Expect(partition.UUID).To(Equal(""))
			})
		})

	})
})

func volumeListWithPartitionSpec(partitionSpec keyserverv1alpha1.PartitionSpec) *keyserverv1alpha1.SealedVolumeList {
	return &keyserverv1alpha1.SealedVolumeList{
		Items: []keyserverv1alpha1.SealedVolume{
			{Spec: keyserverv1alpha1.SealedVolumeSpec{
				TPMHash: "1234",
				Partitions: []keyserverv1alpha1.PartitionSpec{
					partitionSpec,
				},
				Quarantined: false,
			},
			},
		},
	}
}

func volumeListWithAttestationSpec(tpmHash string, attestation *keyserverv1alpha1.AttestationSpec) *keyserverv1alpha1.SealedVolumeList {
	return &keyserverv1alpha1.SealedVolumeList{
		Items: []keyserverv1alpha1.SealedVolume{
			{Spec: keyserverv1alpha1.SealedVolumeSpec{
				TPMHash: tpmHash,
				Partitions: []keyserverv1alpha1.PartitionSpec{
					{
						Label: "COS_PERSISTENT",
						Secret: &keyserverv1alpha1.SecretSpec{
							Name: "test-secret",
							Path: "pass",
						},
					},
				},
				Quarantined: false,
				Attestation: attestation,
			},
			},
		},
	}
}
