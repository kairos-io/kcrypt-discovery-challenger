package client

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/kairos-challenger/pkg/payload"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/yip/pkg/utils"
	"github.com/pkg/errors"
)

const DefaultNVIndex = "0x1500000"

func getPass(server string, headers map[string]string, certificate string, partition *block.Partition) (string, bool, error) {
	opts := []tpm.Option{
		tpm.WithCAs([]byte(certificate)),
		tpm.AppendCustomCAToSystemCA,
		tpm.WithAdditionalHeader("label", partition.FilesystemLabel),
		tpm.WithAdditionalHeader("name", partition.Name),
		tpm.WithAdditionalHeader("uuid", partition.UUID),
	}
	for k, v := range headers {
		opts = append(opts, tpm.WithAdditionalHeader(k, v))
	}

	msg, err := tpm.Get(server, opts...)
	if err != nil {
		return "", false, err
	}
	result := payload.Data{}
	err = json.Unmarshal(msg, &result)
	if err != nil {
		return "", false, errors.Wrap(err, string(msg))
	}

	if result.HasPassphrase() {
		return fmt.Sprint(result.Passphrase), result.HasBeenGenerated() && result.GeneratedBy == constants.TPMSecret, nil
	} else if result.HasError() {
		if strings.Contains(result.Error, "No secret found for") {
			return "", false, errPartNotFound
		}
		if strings.Contains(result.Error, "x509: certificate signed by unknown authority") {
			return "", false, errBadCertificate
		}
		return "", false, fmt.Errorf(result.Error)
	}

	return "", false, errPartNotFound
}

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
	nvindex := DefaultNVIndex
	if k.Kcrypt.Challenger.NVIndex != "" {
		nvindex = k.Kcrypt.Challenger.NVIndex
	}
	opts = append(opts, tpm.WithIndex(nvindex))
	return rand, tpm.StoreBlob(blob, opts...)
}

func localPass(k Config) (string, error) {
	index := DefaultNVIndex
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
