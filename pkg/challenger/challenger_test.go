// [✓] Setup a cluster
// [✓] install crds on it
// - run the server locally
// - make requests to the server to see if we can get passphrases back
package challenger

import (
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
				volumeData := findSecretFor(requestData, volumeList)
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
				volumeData := findSecretFor(requestData, volumeList)
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
				volumeData := findSecretFor(requestData, volumeList)
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
				volumeData := findSecretFor(requestData, volumeList)
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
				volumeData := findSecretFor(requestData, volumeList)
				Expect(volumeData).To(BeNil())
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
