package challenger

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tpm "github.com/kairos-io/tpm-helpers"

	"github.com/kairos-io/kairos-challenger/controllers"
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

func Start(ctx context.Context, kclient *kubernetes.Clientset, reconciler *controllers.SealedVolumeReconciler, namespace, address string) {
	fmt.Println("Challenger started at", address)
	s := http.Server{
		Addr:         address,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()

	m.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
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

			ek, _, err := tpm.GetAttestationData(token)
			if err != nil {
				fmt.Println("Failed getting tpm token")

				fmt.Println("error", err.Error())
				return
			}

			hashEncoded, err := tpm.DecodePubHash(ek)
			if err != nil {
				fmt.Println("error decoding pubhash", err.Error())
				return
			}

			sealedVolumeData := findSecretFor(PassphraseRequestData{
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
				secret, err := kclient.CoreV1().Secrets(namespace).Get(ctx, sealedVolumeData.SecretName, v1.GetOptions{})
				if err == nil {
					passphrase := secret.Data[sealedVolumeData.SecretPath]
					err = json.NewEncoder(writer).Encode(map[string]string{"passphrase": string(passphrase)})
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

func findSecretFor(requestData PassphraseRequestData, volumeList *keyserverv1alpha1.SealedVolumeList) *SealedVolumeData {
	for _, v := range volumeList.Items {
		if requestData.TPMHash == v.Spec.TPMHash {
			for _, p := range v.Spec.Partitions {
				deviceNameMatches := requestData.DeviceName != "" && p.DeviceName == requestData.DeviceName
				uuidMatches := requestData.UUID != "" && p.UUID == requestData.UUID
				labelMatches := requestData.Label != "" && p.Label == requestData.Label

				if labelMatches || uuidMatches || deviceNameMatches {
					return &SealedVolumeData{
						Quarantined: v.Spec.Quarantined,
						SecretName:  p.Secret.Name,
						SecretPath:  p.Secret.Path,
					}
				}
			}
		}
	}

	return nil
}
