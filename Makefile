build:
	go build -o ./bin/sandbox -v ./cmd/sandbox

run: clean build
	./bin/sandbox

clean:
	rm -rf ./bin