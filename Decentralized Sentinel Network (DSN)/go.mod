module github.com/dsn/decentralized-sentinel-network

go 1.21

require (
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.1
	github.com/hyperledger/fabric-sdk-go v1.0.0
	github.com/prometheus/client_golang v1.17.0
	github.com/shirou/gopsutil/v3 v3.23.10
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
	k8s.io/api v0.28.4
	k8s.io/apimachinery v0.28.4
	k8s.io/client-go v0.28.4
)

require (
	github.com/hashicorp/vault/api v1.10.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	go.uber.org/zap v1.26.0
	golang.org/x/crypto v0.15.0
	golang.org/x/net v0.18.0
	golang.org/x/sys v0.14.0
	gopkg.in/yaml.v3 v3.0.1
)