compose-up:
	docker-compose up -d

generate:
	protoc -I  ./auth/proto/auth --go_out=./auth/pkg/pb --go_opt=paths=source_relative --go-grpc_out=./auth/pkg/pb --go-grpc_opt=paths=source_relative ./auth/proto/auth/*.proto


goose-up:
	~/go/bin/goose -dir migrations postgres "postgresql://myuser:1234@localhost:5430/instadb?sslmode=disable" up


goose-down:
	goose -dir migrations postgres "postgresql://myuser:1234@localhost:5430/instadb?sslmode=disable" down
