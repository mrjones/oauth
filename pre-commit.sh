#!/bin/bash
# ln -s pre-commit.sh .git/hooks/pre-commit
go test *.go
if [[ $RESULT != 0 ]]; then exit $RESULT; fi

go fmt *.go
for e in $(ls examples); do 
    go build examples/$e/*.go
    if [[ $RESULT != 0 ]]; then exit $RESULT; fi
    go fmt examples/$e/*.go
done

exit 0
