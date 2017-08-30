DOCKER_VERSION := $(shell git describe --always)

.PHONY: docker
docker: docker-builld.log
	docker tag halflife:$(DOCKER_VERSION) tripleee/halflife:$(DOCKER_VERSION))
	docker tag halflife:$(DOCKER_VERSION) tripleee/halflife:latest
	docker push tripleee/halflife:$(DOCKER_VERSION)

docker-build.log: Dockerfile
	docker build . | tee $@
