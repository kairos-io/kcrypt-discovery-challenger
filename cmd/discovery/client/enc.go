package client

import (
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/yip/pkg/utils"
)

func genAndStore(k Config) (string, error) {
	opts := []tpm.TPMOption{}
	if k.Kcrypt.Challenger.TPMDevice != "" {
		opts = append(opts, tpm.WithDevice(k.Kcrypt.Challenger.TPMDevice))
	}
	if k.Kcrypt.Challenger.CIndex != "" {
		opts = append(opts, tpm.WithIndex(k.Kcrypt.Challenger.CIndex))
	}

	// Generate a new one, and return it to luks
	rand := utils.RandomString(32)
	blob, err := tpm.EncryptBlob([]byte(rand))
	if err != nil {
		return "", err
	}
	nvindex := constants.LocalPassphraseNVIndex
	if k.Kcrypt.Challenger.NVIndex != "" {
		nvindex = k.Kcrypt.Challenger.NVIndex
	}
	opts = append(opts, tpm.WithIndex(nvindex))
	return rand, tpm.StoreBlob(blob, opts...)
}

func localPass(k Config) (string, error) {
	index := constants.LocalPassphraseNVIndex
	if k.Kcrypt.Challenger.NVIndex != "" {
		index = k.Kcrypt.Challenger.NVIndex
	}
	opts := []tpm.TPMOption{tpm.WithIndex(index)}
	if k.Kcrypt.Challenger.TPMDevice != "" {
		opts = append(opts, tpm.WithDevice(k.Kcrypt.Challenger.TPMDevice))
	}
	encodedPass, err := tpm.ReadBlob(opts...)
	if err != nil {
		// Generate if we fail to read from the assigned blob
		return genAndStore(k)
	}

	// Decode and give it back
	opts = []tpm.TPMOption{}
	if k.Kcrypt.Challenger.CIndex != "" {
		opts = append(opts, tpm.WithIndex(k.Kcrypt.Challenger.CIndex))
	}
	if k.Kcrypt.Challenger.TPMDevice != "" {
		opts = append(opts, tpm.WithDevice(k.Kcrypt.Challenger.TPMDevice))
	}
	pass, err := tpm.DecryptBlob(encodedPass, opts...)
	return string(pass), err
}
