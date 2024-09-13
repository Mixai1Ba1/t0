.PHONY: run
run: swagger
	@export PATH=$PATH:$HOME/go/bin
	@export GOOS=darwin
	@export GOARCH=arm64
	@go run main.go

.PHONY: swagger
swagger:
	@swag init

.PHONY: buildM
buildM:
	@go build -o build/main_build     

.PHONY: buildMW
buildMW:
	@export GOOS=windows
	@export GOARCH=amd64
	@go build -o build/main_build.exe  

.PHONY: buildD
buildD:
	@go build -o build/dev_build      

.PHONY: prod
prod:
	@./build/main_build  

