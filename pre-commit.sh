# ln -s pre-commit.sh .git/hooks/pre-commit
go test *.go
go fmt *.go
for e in $(ls examples); do 
    go build examples/$e/*.go
    go fmt examples/$e/*.go
done
