.PHONY: docker .docker-subtarget  symlinks clean
docker: docker-build.log
	docker tag tripleee/halflife tripleee/halflife:latest
	docker push tripleee/halflife:latest

docker-build.log: Dockerfile halflife.py halflife.conf websocketd test
	# Check that we are logged in to Docker, so that push can work
	# https://stackoverflow.com/a/36023944
	awk '/"auths"/ { auth=1 } \
		/^[[:space:]]*\}/ { auth=0 } \
		auth && /"https:\/\/index\.docker\.io\/v1\/":/ { \
			status=1; exit 0 } \
		END { if (!status) \
			  print "No Docker cookie found" >"/dev/stderr";\
			exit 1-status }' ~/.docker/config.json

	# Check that we don't have unpushed commits
	! git log --oneline @{u}.. | grep .

	-awk 'END { print $$NF }' $@ | xargs docker rmi
	docker build -t tripleee/halflife --progress=plain --no-cache . 2>&1 \
	| tee $@

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
