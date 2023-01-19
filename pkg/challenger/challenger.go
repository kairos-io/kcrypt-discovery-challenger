package challenger

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kairos-io/kairos-challenger/controllers"
	tpm "github.com/kairos-io/tpm-helpers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gorilla/websocket"
)

// PassphraseRequestData is a struct that holds all the information needed in
// order to lookup a passphrase for a specific tpm hash.
type PassphraseRequestData struct {
	TPMHash    string
	Label      string
	DeviceName string
	UUID       string
}

type SealedVolumeData struct {
	Quarantined bool
	SecretName  string
	SecretPath  string

	PartitionLabel string
	VolumeName     string
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func writeRead(conn *websocket.Conn, input []byte) ([]byte, error) {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(input); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	_, reader, err := conn.NextReader()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

func getPubHash(token string) (string, error) {
	ek, _, err := tpm.GetAttestationData(token)
	if err != nil {
		return "", err
	}

	return tpm.DecodePubHash(ek)
}

func Start(ctx context.Context, kclient *kubernetes.Clientset, reconciler *controllers.SealedVolumeReconciler, namespace, address string) {
	fmt.Println("Challenger started at", address)
	s := http.Server{
		Addr:         address,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()

	m.HandleFunc("/postPass", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		for {
			if err := tpm.AuthRequest(r, conn); err != nil {
				fmt.Println("error", err.Error())
				return
			}
			defer conn.Close()
			token := r.Header.Get("Authorization")

			hashEncoded, err := getPubHash(token)
			if err != nil {
				fmt.Println("error decoding pubhash", err.Error())
				return
			}

			label := r.Header.Get("label")
			name := r.Header.Get("name")
			uuid := r.Header.Get("uuid")
			v := map[string]string{}

			volumeList := &keyserverv1alpha1.SealedVolumeList{}
			if err := reconciler.List(ctx, volumeList, &client.ListOptions{Namespace: namespace}); err != nil {
				fmt.Println("Failed listing volumes")
				fmt.Println(err)
				continue
			}

			sealedVolumeData := findVolumeFor(PassphraseRequestData{
				TPMHash:    hashEncoded,
				Label:      label,
				DeviceName: name,
				UUID:       uuid,
			}, volumeList)

			if sealedVolumeData == nil {
				fmt.Println("No TPM Hash found for", hashEncoded)
				conn.Close()
				return
			}

			if err := conn.ReadJSON(&v); err != nil {
				fmt.Println("error", err.Error())
				return
			}

			pass, ok := v["passphrase"]
			if ok {
				secretName := fmt.Sprintf("%s-%s", sealedVolumeData.VolumeName, sealedVolumeData.PartitionLabel)
				secretPath := "passphrase"
				if sealedVolumeData.SecretName != "" {
					secretName = sealedVolumeData.SecretName
				}
				if sealedVolumeData.SecretPath != "" {
					secretPath = sealedVolumeData.SecretPath
				}
				_, err := kclient.CoreV1().Secrets(namespace).Get(ctx, secretName, v1.GetOptions{})
				if err != nil {
					if !apierrors.IsNotFound(err) {
						fmt.Printf("Failed getting secret: %s\n", err.Error())
						continue
					}

					secret := corev1.Secret{
						TypeMeta: v1.TypeMeta{
							Kind:       "Secret",
							APIVersion: "apps/v1",
						},
						ObjectMeta: v1.ObjectMeta{
							Name:      secretName,
							Namespace: namespace,
						},
						Data: map[string][]byte{
							secretPath:               []byte(pass),
							constants.GeneratedByKey: []byte(v[constants.GeneratedByKey]),
						},
						Type: "Opaque",
					}
					_, err := kclient.CoreV1().Secrets(namespace).Create(ctx, &secret, v1.CreateOptions{})
					if err != nil {
						fmt.Println("failed during secret creation")
					}
				} else {
					fmt.Println("Posted for already existing secret - ignoring")
				}
			} else {
				fmt.Println("Invalid answer from client: doesn't contain any passphrase")
			}
		}
	})

	m.HandleFunc("/getPass", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity

		for {
			fmt.Println("Received connection")
			volumeList := &keyserverv1alpha1.SealedVolumeList{}
			if err := reconciler.List(ctx, volumeList, &client.ListOptions{Namespace: namespace}); err != nil {
				fmt.Println("Failed listing volumes")
				fmt.Println(err)
				continue
			}

			token := r.Header.Get("Authorization")
			label := r.Header.Get("label")
			name := r.Header.Get("name")
			uuid := r.Header.Get("uuid")

			if err := tpm.AuthRequest(r, conn); err != nil {
				fmt.Println("error validating challenge", err.Error())
				return
			}

			hashEncoded, err := getPubHash(token)
			if err != nil {
				fmt.Println("error decoding pubhash", err.Error())
				return
			}

			sealedVolumeData := findVolumeFor(PassphraseRequestData{
				TPMHash:    hashEncoded,
				Label:      label,
				DeviceName: name,
				UUID:       uuid,
			}, volumeList)

			if sealedVolumeData == nil {
				fmt.Println("No TPM Hash found for", hashEncoded)
				conn.Close()
				return
			}
			writer, _ := conn.NextWriter(websocket.BinaryMessage)
			if !sealedVolumeData.Quarantined {
				secretName := fmt.Sprintf("%s-%s", sealedVolumeData.VolumeName, sealedVolumeData.PartitionLabel)
				secretPath := "passphrase"
				if sealedVolumeData.SecretName != "" {
					secretName = sealedVolumeData.SecretName
				}
				if sealedVolumeData.SecretPath != "" {
					secretPath = sealedVolumeData.SecretPath
				}

				// 1. The admin sets a specific cleartext password from Kube manager
				//      SealedVolume -> with a secret .
				// 2. The admin just adds a SealedVolume associated with a TPM Hash ( you don't provide any passphrase )
				// 3. There is no challenger server at all (offline mode)
				//
				secret, err := kclient.CoreV1().Secrets(namespace).Get(ctx, secretName, v1.GetOptions{})
				if err == nil {
					passphrase := secret.Data[secretPath]
					generatedBy, generated := secret.Data[constants.GeneratedByKey]
					result := map[string]string{"passphrase": string(passphrase)}
					if generated {
						result[constants.GeneratedByKey] = string(generatedBy)
					}
					err = json.NewEncoder(writer).Encode(result)
					if err != nil {
						fmt.Println("error encoding the passphrase to json", err.Error(), string(passphrase))
					}
					if err = writer.Close(); err != nil {
						fmt.Println("error closing the writer", err.Error())
						return
					}
					if err = conn.Close(); err != nil {
						fmt.Println("error closing the connection", err.Error())
						return
					}

					return
				}
			} else {
				fmt.Println("error getting the secret", err.Error())
				if err = conn.Close(); err != nil {
					fmt.Println("error closing the connection", err.Error())
					return
				}
				return
			}
		}
	},
	)

	s.Handler = m

	go func() {
		err := s.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
	}()
}

func findVolumeFor(requestData PassphraseRequestData, volumeList *keyserverv1alpha1.SealedVolumeList) *SealedVolumeData {
	for _, v := range volumeList.Items {
		if requestData.TPMHash == v.Spec.TPMHash {
			for _, p := range v.Spec.Partitions {
				deviceNameMatches := requestData.DeviceName != "" && p.DeviceName == requestData.DeviceName
				uuidMatches := requestData.UUID != "" && p.UUID == requestData.UUID
				labelMatches := requestData.Label != "" && p.Label == requestData.Label

				if labelMatches || uuidMatches || deviceNameMatches {
					return &SealedVolumeData{
						Quarantined:    v.Spec.Quarantined,
						SecretName:     p.Secret.Name,
						SecretPath:     p.Secret.Path,
						VolumeName:     v.Name,
						PartitionLabel: p.Label,
					}
				}
			}
		}
	}

	return nil
}
