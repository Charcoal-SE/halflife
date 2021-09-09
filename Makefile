.PHONY: docker .docker-subtarget  symlinks clean
docker: docker-build.log
	docker tag tripleee/halflife tripleee/halflife:latest
	docker push tripleee/halflife:latest

docker-build.log: Dockerfile halflife.py halflife.conf websocketd test
	# Check that we don't have unpushed commits
	! git log --oneline @{u}.. | grep .
	-awk 'END { print $$NF }' $@ | xargs docker rmi
	docker build -t tripleee/halflife --no-cache . | tee $@

websocketd: ../websocketd-alpine/websocketd
	cp $< $@


.PHONY: test
test: hlenv
	./hlenv/bin/python ./nst.py nst.json

hlenv: requirements.txt
	$(RM) -r $@
	python3 -m venv $@
	$@/bin/pip install -r requirements.txt


SYMLINKS := blacklisted_websites.txt \
	$(patsubst %,%_numbers.txt,watched blacklisted) \
	$(patsubst %,%_keywords.txt,watched bad)
symlinks: $(SYMLINKS)
$(SYMLINKS): %: ../SmokeDetector/%
	test -p $@ || ln -s $< $@


clean:
	:
realclean: clean
	$(RM) $(SYMLINKS)
distclean: realclean
	$(RM) *.log
	# Manually remove halflife.conf if you are really dramatic
