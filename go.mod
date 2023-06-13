module github.com/kairos-io/kairos-challenger

go 1.20

// The address is github.com/kairos-io/kairos-agent but the go module is called differently
replace github.com/kairos-io/kairos/v2 v2.1.3 => github.com/kairos-io/kairos-agent/v2 v2.1.3

require (
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.5.0
	github.com/jaypipes/ghw v0.10.0
	github.com/kairos-io/kairos/v2 v2.1.3
	github.com/kairos-io/kcrypt v0.5.3-0.20230504121015-f5dc23f5548a
	github.com/kairos-io/tpm-helpers v0.0.0-20230119140150-3fa97128ef6b
	github.com/mudler/go-pluggable v0.0.0-20230126220627-7710299a0ae5
	github.com/mudler/go-processmanager v0.0.0-20220724164624-c45b5c61312d
	github.com/mudler/yip v1.0.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/ginkgo/v2 v2.9.2
	github.com/onsi/gomega v1.27.6
	github.com/pkg/errors v0.9.1
	github.com/spectrocloud/peg v0.0.0-20230407121159-2e15270c4a46
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.24.2
	k8s.io/apimachinery v0.24.2
	k8s.io/client-go v0.24.2
	sigs.k8s.io/controller-runtime v0.12.2
)

require (
	atomicgo.dev/cursor v0.1.1 // indirect
	atomicgo.dev/keyboard v0.2.9 // indirect
	cloud.google.com/go v0.93.3 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.18 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.13 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/anatol/devmapper.go v0.0.0-20220907161421-ba4de5fc0fd1 // indirect
	github.com/anatol/luks.go v0.0.0-20230125211543-ada2562d4206 // indirect
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/aybabtme/rgbterm v0.0.0-20170906152045-cc83f3b3ce59 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bramvdbogaerde/go-scp v1.2.1 // indirect
	github.com/cavaliergopher/grab/v3 v3.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/chuckpreslar/emission v0.0.0-20170206194824-a7ddd980baf9 // indirect
	github.com/codingsince1985/checksum v1.2.6 // indirect
	github.com/containerd/console v1.0.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/folbricht/tpmk v0.1.2-0.20230104073416-f20b20c289d7 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/zapr v1.2.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-attestation v0.4.4-0.20220404204839-8820d49b18d9 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/go-tpm-tools v0.3.10 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20230228050547-1710fef4ab10 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gookit/color v1.5.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/itchyny/gojq v0.12.12 // indirect
	github.com/itchyny/timefmt-go v0.1.5 // indirect
	github.com/jaypipes/pcidb v1.0.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kairos-io/kairos v1.24.3-56.0.20230329142538-b6ae4b58c07d // indirect
	github.com/kairos-io/kairos-sdk v0.0.2-0.20230414094028-0c9d2bd9e6ae // indirect
	github.com/lithammer/fuzzysearch v1.1.5 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/otiai10/copy v1.9.0 // indirect
	github.com/phayes/freeport v0.0.0-20220201140144-74d24b5ae9f5 // indirect
	github.com/prometheus/client_golang v1.13.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/pterm/pterm v0.12.59 // indirect
	github.com/qeesung/image2ascii v1.0.1 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/swaggest/jsonschema-go v0.3.49 // indirect
	github.com/swaggest/refl v1.1.0 // indirect
	github.com/twpayne/go-vfs v1.7.2 // indirect
	github.com/urfave/cli v1.22.12 // indirect
	github.com/wayneashleyberry/terminal-dimensions v1.1.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20220916125017-b168a2c6b86b // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/oauth2 v0.7.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/term v0.7.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	golang.org/x/tools v0.7.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v1.0.0 // indirect
	k8s.io/apiextensions-apiserver v0.24.2 // indirect
	k8s.io/component-base v0.24.2 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42 // indirect
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9 // indirect
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
